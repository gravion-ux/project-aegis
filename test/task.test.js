'use strict';

/**
 * Task model tests.
 *
 * These were referenced by `package.json` from Phase 1 but the file was
 * never written — Node's test runner silently ignores a path that does not
 * exist, so the gap was invisible in every green run. The Task model is the
 * core state machine of the system, so it now has real coverage.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { Task } = require('../aegis/task');
const { STATES, canTransition } = require('../aegis/states');

test('task: a new task starts QUEUED with sensible defaults', () => {
  const t = new Task({});
  assert.equal(t.state, STATES.QUEUED);
  assert.equal(t.title, '(untitled)');
  assert.equal(t.role, 'coding');
  assert.equal(t.goal, '');
  assert.deepEqual(t.input, {});
  assert.equal(t.output, null);
  assert.deepEqual(t.evidence, []);
  assert.equal(t.error, null);
  assert.equal(t.retries, 0);
});

test('task: id is generated and unique', () => {
  const a = new Task({});
  const b = new Task({});
  assert.match(a.id, /^t_[0-9a-f]{16}$/);
  assert.notEqual(a.id, b.id);
});

test('task: an explicit id is preserved', () => {
  const t = new Task({ id: 't_fixed' });
  assert.equal(t.id, 't_fixed');
});

test('task: creation is recorded as the first transition', () => {
  const t = new Task({});
  assert.equal(t.transitions.length, 1);
  assert.equal(t.transitions[0].from, null);
  assert.equal(t.transitions[0].to, STATES.QUEUED);
  assert.equal(t.transitions[0].note, 'created');
});

test('task: a valid transition appends a record and bumps updatedAt', () => {
  const t = new Task({});
  const before = t.updatedAt;
  const rec = t.transition(STATES.READY, { note: 'picked up' });
  assert.equal(t.state, STATES.READY);
  assert.equal(t.transitions.length, 2);
  assert.equal(rec.from, STATES.QUEUED);
  assert.equal(rec.to, STATES.READY);
  assert.equal(rec.note, 'picked up');
  assert.equal(rec.actor, 'system');
  assert.ok(t.updatedAt >= before);
});

test('task: an invalid transition throws and leaves state untouched', () => {
  const t = new Task({});
  assert.throws(() => t.transition(STATES.SUCCEEDED), /transition/i);
  assert.equal(t.state, STATES.QUEUED);
  assert.equal(t.transitions.length, 1, 'a rejected transition must not be recorded');
});

test('task: transition to FAILED captures the error', () => {
  const t = new Task({});
  t.transition(STATES.READY);
  t.transition(STATES.RUNNING);
  t.transition(STATES.FAILED, { error: 'boom' });
  assert.equal(t.error, 'boom');
});

test('task: transition to RETRYING increments the retry counter', () => {
  const t = new Task({});
  t.transition(STATES.READY);
  t.transition(STATES.RUNNING);
  t.transition(STATES.FAILED, { error: 'transient' });
  t.transition(STATES.RETRYING);
  assert.equal(t.retries, 1);
});

test('task: RETRYING is reachable only from FAILED', () => {
  // A retry must be earned by a failure — a task may not jump straight from
  // RUNNING into a retry, or a failed agent could spin without ever failing.
  const t = new Task({});
  t.transition(STATES.READY);
  t.transition(STATES.RUNNING);
  assert.equal(canTransition(STATES.RUNNING, STATES.RETRYING), false);
  assert.throws(() => t.transition(STATES.RETRYING), /invalid transition/);
  assert.equal(t.state, STATES.RUNNING);
});

test('task: attachOutput sets the output and bumps updatedAt', () => {
  const t = new Task({});
  const before = t.updatedAt;
  t.attachOutput({ buckets: ['auth'] });
  assert.deepEqual(t.output, { buckets: ['auth'] });
  assert.ok(t.updatedAt >= before);
});

test('task: addEvidence stamps each entry with a timestamp', () => {
  const t = new Task({});
  t.addEvidence({ kind: 'classification', buckets: ['auth'] });
  assert.equal(t.evidence.length, 1);
  assert.equal(t.evidence[0].kind, 'classification');
  assert.ok(t.evidence[0].ts, 'evidence must be timestamped');
});

test('task: addEvidence tolerates an empty entry', () => {
  const t = new Task({});
  t.addEvidence();
  assert.equal(t.evidence.length, 1);
  assert.ok(t.evidence[0].ts);
});

test('task: toJSON round-trips through fromJSON', () => {
  const t = new Task({ id: 't_1', title: 'audit', role: 'review', goal: 'look', input: { text: 'x' } });
  t.transition(STATES.READY);
  t.transition(STATES.RUNNING);
  t.attachOutput({ score: 90 });
  t.addEvidence({ kind: 'review' });

  const restored = Task.fromJSON(JSON.parse(JSON.stringify(t)));
  assert.equal(restored.id, t.id);
  assert.equal(restored.title, t.title);
  assert.equal(restored.role, t.role);
  assert.equal(restored.goal, t.goal);
  assert.deepEqual(restored.input, t.input);
  assert.equal(restored.state, t.state);
  assert.equal(restored.transitions.length, t.transitions.length);
  assert.deepEqual(restored.output, t.output);
  assert.equal(restored.evidence.length, 1);
  assert.equal(restored.createdAt, t.createdAt);
  assert.equal(restored.updatedAt, t.updatedAt);
});

test('task: fromJSON rejects an object without an id', () => {
  assert.throws(() => Task.fromJSON({}), /missing id/);
  assert.throws(() => Task.fromJSON(null), /missing id/);
});

test('task: fromJSON falls back to safe defaults for absent fields', () => {
  const t = Task.fromJSON({ id: 't_1' });
  assert.equal(t.state, STATES.QUEUED);
  assert.equal(t.title, '(untitled)');
  assert.equal(t.role, 'coding');
  assert.deepEqual(t.evidence, []);
  assert.equal(t.retries, 0);
  assert.equal(t.output, null);
});

test('task: fromJSON ignores a non-array transitions field', () => {
  const t = Task.fromJSON({ id: 't_1', transitions: 'not-an-array' });
  assert.ok(Array.isArray(t.transitions));
  assert.equal(t.transitions.length, 1);
});

test('task: the full happy path runs QUEUED to SUCCEEDED', () => {
  const t = new Task({});
  t.transition(STATES.READY);
  t.transition(STATES.RUNNING);
  t.attachOutput({ ok: true });
  t.transition(STATES.SUCCEEDED);
  assert.equal(t.state, STATES.SUCCEEDED);
  assert.equal(t.transitions.length, 4);
  assert.deepEqual(t.transitions.map((x) => x.to), [
    STATES.QUEUED, STATES.READY, STATES.RUNNING, STATES.SUCCEEDED,
  ]);
});

test('task: the CANCELLED path is reachable from RUNNING', () => {
  const t = new Task({});
  t.transition(STATES.READY);
  t.transition(STATES.RUNNING);
  assert.ok(canTransition(STATES.RUNNING, STATES.CANCELLED));
  t.transition(STATES.CANCELLED);
  assert.equal(t.state, STATES.CANCELLED);
});
