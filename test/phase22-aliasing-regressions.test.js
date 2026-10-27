'use strict';

/**
 * Phase 2.2 regressions — identifier aliasing family (P22-30 … P22-36).
 *
 * Every test in this file reproduces a defect that was confirmed against the
 * *published* Phase 2.2 code before it was fixed. The shared theme: two
 * identifiers that resolve to the same file on a case-insensitive filesystem
 * (Windows, macOS) silently shared, overwrote or destroyed one another's
 * records — while behaving differently on Linux, where the two names are
 * separate files.
 *
 * The fixes compare identifiers and filenames directly instead of trusting
 * the host filesystem, so the behaviour is the same on every platform.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { Storage } = require('../aegis/storage');
const { CheckpointStore, Checkpoint } = require('../aegis/recovery');
const { Memory } = require('../aegis/memory');
const { Task } = require('../aegis/task');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(require('node:os').tmpdir(), prefix));
}

/**
 * A valid checkpoint step. The checkpoint loader rejects primitive entries,
 * so the aliasing tests must use real step objects — otherwise they would
 * trip the shape validation instead of exercising the aliasing guard.
 */
function step(seq, name) {
  return { seq, name, idempotencyKey: `k${seq}` };
}

// ---------------------------------------------------------------------------
// P22-30: a task id that differs from `_index` only by case clobbers the index
// ---------------------------------------------------------------------------

test('P22-30: a task id differing from the index name only by case is refused', () => {
  const dir = tmpDir('aegis-p22-30-');
  try {
    const store = new Storage(dir);
    store.put(new Task({ id: 'ordinary', role: 'coding' }));

    // `_INDEX` resolves to `_index.json` on Windows and macOS.
    assert.throws(
      () => store.put(new Task({ id: '_INDEX', role: 'coding' })),
      (err) => err.code === 'INVALID_ID',
      'a case-variant of the index name was accepted',
    );

    // The index must still hold the original task.
    const index = JSON.parse(fs.readFileSync(path.join(dir, '_index.json'), 'utf-8'));
    assert.deepEqual(Object.keys(index.tasks), ['ordinary']);
    assert.ok(store.get('ordinary'), 'the ordinary task was lost');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// P22-31: remove() with a case-variant id deletes another task's record
// ---------------------------------------------------------------------------

test('P22-31: removing a task by a case-variant id does not delete another task', () => {
  const dir = tmpDir('aegis-p22-31-');
  try {
    const store = new Storage(dir);
    store.put(new Task({ id: 'Alpha', role: 'coding' }));
    store.put(new Task({ id: 'Beta', role: 'coding' }));

    // `alpha` resolves to `Alpha.json` on a case-insensitive filesystem.
    store.remove('alpha');

    assert.ok(store.get('Alpha'), 'Alpha was destroyed by removing "alpha"');
    assert.ok(fs.existsSync(path.join(dir, 'Alpha.json')), 'Alpha.json was unlinked');
    assert.ok(store.get('Beta'), 'Beta was affected');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// P22-32: CheckpointStore.clear() with a case-variant id deletes a checkpoint
// ---------------------------------------------------------------------------

test('P22-32: clearing a checkpoint by a case-variant id does not delete another checkpoint', () => {
  const dir = tmpDir('aegis-p22-32-');
  try {
    const store = new CheckpointStore(dir);
    store.save(new Checkpoint({ taskId: 'Alpha', completed: [step(1, 'a')], pending: [step(2, 'b')], lastSeq: 1 }));
    store.save(new Checkpoint({ taskId: 'Beta', completed: [step(1, 'c')], pending: [], lastSeq: 1 }));

    store.clear('alpha');

    assert.ok(store.load('Alpha'), 'Alpha\'s checkpoint was destroyed by clearing "alpha"');
    assert.ok(fs.existsSync(path.join(dir, 'Alpha.checkpoint.json')));
    assert.ok(store.load('Beta'), 'Beta\'s checkpoint was affected');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// P22-33: CheckpointStore.save() with a case-variant id overwrites a checkpoint
// ---------------------------------------------------------------------------

test('P22-33: saving a checkpoint under a case-variant id is refused', () => {
  const dir = tmpDir('aegis-p22-33-');
  try {
    const store = new CheckpointStore(dir);
    store.save(new Checkpoint({ taskId: 'Alpha', completed: [step(1, 'alpha-work')], pending: [], lastSeq: 1 }));

    assert.throws(
      () => store.save(new Checkpoint({ taskId: 'alpha', completed: [step(2, 'lower-work')], pending: [], lastSeq: 1 })),
      (err) => err.code === 'TASK_ID_CONFLICT',
      'a case-variant id overwrote another task\'s checkpoint',
    );

    const loaded = store.load('Alpha');
    assert.deepEqual(loaded.completed.map((s) => s.name), ['alpha-work'], 'Alpha\'s checkpoint was overwritten');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// P22-34: Memory leaks records across projects that differ only by case
// ---------------------------------------------------------------------------

test('P22-34: memory records do not leak between projects that differ only by case', () => {
  const dir = tmpDir('aegis-p22-34-');
  try {
    const mem = new Memory(dir);
    mem.add('ProjectX', { key: 'k1', value: 'from-ProjectX', type: 'fact' });

    assert.throws(
      () => mem.add('projectx', { key: 'k2', value: 'from-projectx', type: 'fact' }),
      (err) => err.code === 'PROJECT_ID_CONFLICT',
      'a case-variant project id was accepted',
    );

    const upper = mem.list('ProjectX');
    assert.equal(upper.length, 1, 'records leaked into the other project');
    assert.equal(upper[0].key, 'k1');
    assert.ok(!upper.some((r) => r.value === 'from-projectx'), 'the other project\'s record leaked');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// P22-35: Memory.loadCheckpoint() returns another project's checkpoint
// ---------------------------------------------------------------------------

test('P22-35: a memory checkpoint is only served to the project that wrote it', () => {
  const dir = tmpDir('aegis-p22-35-');
  try {
    const mem = new Memory(dir);
    mem.saveCheckpoint('ProjectX', { objective: 'PROJECT-X-OBJECTIVE' });

    const loaded = mem.loadCheckpoint('projectx');
    assert.equal(loaded, null, 'another project\'s checkpoint was served');

    // The rightful owner still gets it.
    const own = mem.loadCheckpoint('ProjectX');
    assert.ok(own, 'the checkpoint is not served to its own project');
    assert.equal(own.objective, 'PROJECT-X-OBJECTIVE');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// P22-36: a task id ending in `.checkpoint` collides with the checkpoint
//           namespace of another task
// ---------------------------------------------------------------------------

test('P22-36: a task id ending in ".checkpoint" cannot overwrite another task\'s checkpoint', () => {
  const dir = tmpDir('aegis-p22-36-');
  try {
    const store = new Storage(dir);
    const checkpoints = new CheckpointStore(dir);
    store.put(new Task({ id: 'x', role: 'coding' }));
    checkpoints.save(new Checkpoint({ taskId: 'x', completed: [step(1, 'step-1')], pending: [step(2, 'step-2')], lastSeq: 1 }));

    // `x.checkpoint` resolves to `x.checkpoint.json`, which is task x's
    // checkpoint file.
    assert.throws(
      () => store.put(new Task({ id: 'x.checkpoint', role: 'coding' })),
      (err) => err.code === 'TASK_ID_CONFLICT',
      'a task id in the checkpoint namespace was accepted',
    );

    const loaded = checkpoints.load('x');
    assert.ok(loaded, 'task x\'s checkpoint was destroyed');
    assert.deepEqual(loaded.completed.map((s) => s.name), ['step-1']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
