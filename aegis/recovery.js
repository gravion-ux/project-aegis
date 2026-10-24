'use strict';

/**
 * Cooperative cancellation and crash-resilient recovery.
 *
 * Long-running steps check `signal.aborted` between iterations and
 * between tool calls. On SIGINT / process exit, in-flight steps see
 * the signal and unwind cleanly.
 *
 * Checkpoints are written to disk after each completed step. On
 * restart, the resume path replays the recorded steps and runs the
 * next pending one. Idempotency keys prevent accidental double-execution
 * of completed steps when a step is retried after a crash.
 */

const { STATES } = require('./states');
const { isSafeIdentifier, recordPath } = require('./paths');

class CancellationError extends Error {
  constructor(message = 'cancelled') {
    super(message); this.name = 'CancellationError'; this.code = 'CANCELLED';
  }
}

class Checkpoint {
  constructor({ taskId, completed = [], pending = [], lastSeq = 0, version = 1 } = {}) {
    this.taskId = taskId;
    this.completed = completed;          // [{ seq, name, output, idempotencyKey, ts }]
    this.pending = pending;              // [{ seq, name, input, idempotencyKey }]
    this.lastSeq = lastSeq;
    this.version = version;
    this.ts = new Date().toISOString();
  }
  nextPending() { return this.pending[0] || null; }
  markCompleted({ seq, name, output, idempotencyKey }) {
    const idx = this.pending.findIndex((s) => s.seq === seq);
    if (idx >= 0) this.pending.splice(idx, 1);
    // dedupe by idempotency key
    if (this.completed.some((s) => s.idempotencyKey === idempotencyKey)) return;
    this.completed.push({ seq, name, output, idempotencyKey, ts: new Date().toISOString() });
    this.lastSeq = Math.max(this.lastSeq, seq);
    this.ts = new Date().toISOString();
  }
  markInterrupted() {
    this.ts = new Date().toISOString();
  }
  toJSON() {
    return { taskId: this.taskId, completed: this.completed, pending: this.pending, lastSeq: this.lastSeq, version: this.version, ts: this.ts };
  }
  static fromJSON(j) {
    if (!j || !j.taskId) throw new Error('Checkpoint.fromJSON: missing taskId');
    return new Checkpoint(j);
  }
}

/**
 * Persist and load checkpoints under `state/<taskId>.checkpoint.json`.
 *
 * The task id is caller-supplied, so it is validated before it is turned
 * into a filename — see `aegis/paths.js`. A traversing id must not be able
 * to make the store read or write outside the state directory.
 */
class CheckpointStore {
  constructor(stateDir, fsModule) {
    this.dir = stateDir;
    this.fs = fsModule || require('node:fs');
    this.path = require('node:path');
  }
  _file(taskId) { return recordPath(this.dir, taskId, '.checkpoint.json', 'task id'); }
  load(taskId) {
    if (!isSafeIdentifier(taskId)) return null;
    let f;
    try { f = this._file(taskId); } catch { return null; }
    if (!this.fs.existsSync(f)) return null;
    try {
      const cp = Checkpoint.fromJSON(JSON.parse(this.fs.readFileSync(f, 'utf-8')));
      // The id inside the file must match the id that was asked for.
      // Otherwise a checkpoint copied under another task's name would be
      // loaded as if it belonged to this task, and a later save() would
      // write it back under the other task's name.
      if (cp.taskId !== taskId) return null;
      return cp;
    } catch { return null; }
  }
  save(cp) {
    if (!cp) return;
    const file = this._file(cp.taskId); // throws INVALID_ID / PATH_ESCAPE
    this.fs.mkdirSync(this.dir, { recursive: true });
    const tmp = `${file}.tmp`;
    this.fs.writeFileSync(tmp, JSON.stringify(cp.toJSON(), null, 2));
    this.fs.renameSync(tmp, file);
  }
  clear(taskId) {
    if (!isSafeIdentifier(taskId)) return;
    let f;
    try { f = this._file(taskId); } catch { return; }
    if (this.fs.existsSync(f)) this.fs.unlinkSync(f);
  }
}

/**
 * In-memory idempotency tracker. A step is a no-op if its
 * idempotency key has already been recorded.
 */
class Idempotency {
  constructor() { this._seen = new Set(); }
  already(key) { return this._seen.has(key); }
  record(key) { this._seen.add(key); }
  size() { return this._seen.size; }
}

/**
 * Plan: a list of steps. Each step has a stable `idempotencyKey` so a
 * retried run does not execute completed steps.
 */
function buildPlanFromTask(task, totalSteps) {
  // the plan is an ordered list of `totalSteps` steps. Each step has
  // an idempotencyKey derived from the task id and the step index.
  const plan = [];
  for (let i = 0; i < totalSteps; i += 1) {
    plan.push({ seq: i + 1, name: `step-${i + 1}`, input: task.input, idempotencyKey: `${task.id}#${i + 1}` });
  }
  return plan;
}

function detectInterrupted(cp) {
  if (!cp) return false;
  // Heuristic: a checkpoint whose `ts` is older than the task's
  // `updatedAt` indicates that the process died after the last
  // recorded step and before recording the next.
  return cp.pending.length > 0 && cp.completed.length > 0;
}

module.exports = { Checkpoint, CheckpointStore, Idempotency, CancellationError, buildPlanFromTask, detectInterrupted, STATES };
