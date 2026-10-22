'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const {
  Checkpoint, CheckpointStore, Idempotency, CancellationError,
  buildPlanFromTask, detectInterrupted,
} = require('../aegis/recovery');
const { Task } = require('../aegis/task');

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-recovery-')); }

// ---- checkpoint model ----

test('checkpoint: new checkpoint has empty completed/pending', () => {
  const cp = new Checkpoint({ taskId: 't1' });
  assert.equal(cp.completed.length, 0);
  assert.equal(cp.pending.length, 0);
  assert.equal(cp.version, 1);
});

test('checkpoint: markCompleted moves a step out of pending', () => {
  const cp = new Checkpoint({ taskId: 't1', pending: [{ seq: 1, name: 'a', idempotencyKey: 't1#1' }] });
  cp.markCompleted({ seq: 1, name: 'a', output: 'ok', idempotencyKey: 't1#1' });
  assert.equal(cp.pending.length, 0);
  assert.equal(cp.completed.length, 1);
  assert.equal(cp.lastSeq, 1);
});

test('checkpoint: markCompleted dedupes by idempotency key', () => {
  const cp = new Checkpoint({ taskId: 't1', pending: [{ seq: 1, name: 'a', idempotencyKey: 'k1' }] });
  cp.markCompleted({ seq: 1, name: 'a', idempotencyKey: 'k1' });
  cp.markCompleted({ seq: 1, name: 'a', idempotencyKey: 'k1' });
  assert.equal(cp.completed.length, 1, 'idempotent: no duplicate');
});

test('checkpoint: JSON round-trip', () => {
  const cp = new Checkpoint({ taskId: 't1' });
  cp.markCompleted({ seq: 1, name: 'a', output: { x: 1 }, idempotencyKey: 't1#1' });
  const back = Checkpoint.fromJSON(JSON.parse(JSON.stringify(cp)));
  assert.equal(back.taskId, 't1');
  assert.equal(back.completed.length, 1);
});

test('checkpoint: fromJSON rejects missing taskId', () => {
  assert.throws(() => Checkpoint.fromJSON({}), /missing taskId/);
});

// ---- checkpoint store ----

test('CheckpointStore: save + load round-trips across instances', () => {
  const dir = tmp();
  const cp = new Checkpoint({ taskId: 't1' });
  cp.markCompleted({ seq: 1, name: 'a', idempotencyKey: 't1#1' });
  const store1 = new CheckpointStore(dir);
  store1.save(cp);
  // a brand new store object = a "new process"
  const store2 = new CheckpointStore(dir);
  const loaded = store2.load('t1');
  assert.equal(loaded.taskId, 't1');
  assert.equal(loaded.completed.length, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CheckpointStore: load returns null when no checkpoint exists', () => {
  const dir = tmp();
  const store = new CheckpointStore(dir);
  assert.equal(store.load('nope'), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CheckpointStore: corrupted checkpoint file loads as null', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 't1.checkpoint.json'), '{ broken');
  const store = new CheckpointStore(dir);
  assert.equal(store.load('t1'), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CheckpointStore: clear removes the file', () => {
  const dir = tmp();
  const store = new CheckpointStore(dir);
  store.save(new Checkpoint({ taskId: 't1' }));
  store.clear('t1');
  assert.equal(store.load('t1'), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---- idempotency ----

test('Idempotency: tracks seen keys', () => {
  const id = new Idempotency();
  assert.equal(id.already('k1'), false);
  id.record('k1');
  assert.equal(id.already('k1'), true);
  assert.equal(id.size(), 1);
});

// ---- plan + interrupted detection ----

test('buildPlanFromTask: creates one step per requested count with stable keys', () => {
  const t = new Task({ role: 'echo' });
  const plan = buildPlanFromTask(t, 3);
  assert.equal(plan.length, 3);
  assert.equal(plan[0].idempotencyKey, `${t.id}#1`);
  assert.equal(plan[2].idempotencyKey, `${t.id}#3`);
});

test('detectInterrupted: true when some completed and some pending remain', () => {
  const cp = new Checkpoint({
    taskId: 't1',
    completed: [{ seq: 1, name: 'a', idempotencyKey: 'k1' }],
    pending: [{ seq: 2, name: 'b', idempotencyKey: 'k2' }],
  });
  assert.equal(detectInterrupted(cp), true);
});

test('detectInterrupted: false for a fully completed run', () => {
  const cp = new Checkpoint({ taskId: 't1', completed: [{ seq: 1, idempotencyKey: 'k1' }], pending: [] });
  assert.equal(detectInterrupted(cp), false);
});

test('CancellationError carries the CANCELLED code', () => {
  assert.equal(new CancellationError().code, 'CANCELLED');
});

// ---- restart survival (real subprocess) ----

test('recovery: a multi-step run survives a process restart without repeating completed steps', () => {
  const dir = tmp();
  const script = path.join(dir, 'runner.js');
  // The runner performs N steps, persisting a checkpoint after each.
  // We run it with MAX_STEPS=2 first (simulating a crash), then restart it
  // with MAX_STEPS=5 and assert that steps 1-2 are NOT re-executed.
  fs.writeFileSync(script, `
'use strict';
const path = require('node:path');
const { Checkpoint, CheckpointStore, Idempotency, buildPlanFromTask } = require(${JSON.stringify(path.resolve(__dirname, '..', 'aegis', 'recovery.js'))});
const { Task } = require(${JSON.stringify(path.resolve(__dirname, '..', 'aegis', 'task.js'))});

const stateDir = process.argv[2];
const maxSteps = Number(process.argv[3]);

const task = new Task({ role: 'echo', id: 't_restart', title: 'restart demo' });
const store = new CheckpointStore(stateDir);
let cp = store.load(task.id) || new Checkpoint({ taskId: task.id, pending: buildPlanFromTask(task, 5) });
const idem = new Idempotency();
cp.completed.forEach((s) => idem.record(s.idempotencyKey));

const executed = [];
while (cp.pending.length > 0 && executed.length < maxSteps) {
  const step = cp.nextPending();
  if (idem.already(step.idempotencyKey)) { break; }
  executed.push(step.seq);
  cp.markCompleted({ seq: step.seq, name: step.name, output: 'ok', idempotencyKey: step.idempotencyKey });
  idem.record(step.idempotencyKey);
  store.save(cp);
}
console.log(JSON.stringify({ executed, completed: cp.completed.length, pending: cp.pending.length }));
`);

  const first = spawnSync(process.execPath, [script, dir, '2'], { encoding: 'utf-8', timeout: 15_000 });
  const firstJson = JSON.parse(first.stdout.trim().split('\n').pop());
  assert.deepEqual(firstJson.executed, [1, 2], 'first run executes steps 1-2');
  assert.equal(firstJson.pending, 3, '3 steps still pending');

  const second = spawnSync(process.execPath, [script, dir, '5'], { encoding: 'utf-8', timeout: 15_000 });
  const secondJson = JSON.parse(second.stdout.trim().split('\n').pop());
  assert.deepEqual(secondJson.executed, [3, 4, 5], 'restart resumes at step 3, does not repeat 1-2');
  assert.equal(secondJson.pending, 0, 'all steps complete');
  assert.equal(secondJson.completed, 5);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('recovery: idempotency prevents double execution after a retry', () => {
  const dir = tmp();
  const task = new Task({ role: 'echo', id: 't_idem' });
  const store = new CheckpointStore(dir);
  const cp = new Checkpoint({ taskId: task.id, pending: buildPlanFromTask(task, 3) });
  const idem = new Idempotency();

  const step = cp.nextPending();
  cp.markCompleted({ seq: step.seq, name: step.name, idempotencyKey: step.idempotencyKey });
  idem.record(step.idempotencyKey);
  store.save(cp);

  // simulate a retry: reload and try the same step key again
  const reloaded = store.load(task.id);
  assert.equal(idem.already(step.idempotencyKey), true);
  assert.equal(reloaded.completed.length, 1, 'step recorded exactly once');

  fs.rmSync(dir, { recursive: true, force: true });
});