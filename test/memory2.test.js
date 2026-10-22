'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Memory, validate, normalize, MEMORY_TYPES } = require('../aegis/memory');

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-mem-')); }

test('memory2: validate rejects missing fields', () => {
  assert.ok(validate({}).match(/missing field/));
  assert.ok(validate({ id: 'm_1' }).match(/missing field/));
  assert.ok(validate({ id: 'm_1', projectId: 'p1' }).match(/missing field/));
  assert.ok(validate({ id: 'm_1', projectId: 'p1', key: 'k', value: 'v', ts: '2025-01-01T00:00:00Z' }).match(/missing field/));
  assert.equal(validate({ id: 'm_1', projectId: 'p1', key: 'k', value: 'v', ts: '2025-01-01T00:00:00Z', type: 'fact' }), null);
  assert.ok(validate({ broken: true }).match(/missing field/));
});

test('memory2: validate rejects unknown type', () => {
  const err = validate({ id: 'm_1', projectId: 'p1', key: 'k', value: 'v', ts: 't', type: 'banana' });
  assert.match(err, /unknown memory type/);
});

test('memory2: validate rejects out-of-range confidence', () => {
  const err = validate({ id: 'm_1', projectId: 'p1', key: 'k', value: 'v', ts: 't', type: 'fact', confidence: 2.5 });
  assert.match(err, /confidence/);
});

test('memory2: add + get round-trip with new schema', () => {
  const root = tmp();
  const m = new Memory(root);
  const r = m.add('p1', { key: 'scope', value: 'https://127.0.0.1:8000', type: 'fact', tags: ['auth'], confidence: 0.9 });
  assert.equal(r.type, 'fact');
  assert.equal(r.confidence, 0.9);
  assert.equal(r.tags[0], 'auth');
  const got = m.get(r.id, 'p1');
  assert.equal(got.id, r.id);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: exact duplicate add returns existing record (dedup)', () => {
  const root = tmp();
  const m = new Memory(root);
  const a = m.add('p1', { key: 'x', value: '1', type: 'fact' });
  const b = m.add('p1', { key: 'x', value: '1', type: 'fact' });
  assert.equal(a.id, b.id, 'expected the same id (dedup)');
  assert.equal(m.list('p1').length, 1);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: near-duplicate merge when opted in', () => {
  const root = tmp();
  const m = new Memory(root);
  const a = m.add('p1', { key: 'k', value: 'hello', tags: ['a'], type: 'fact' });
  const b = m.add('p1', { key: 'k', value: 'hello', tags: ['b'], type: 'fact' }, { onNearDuplicate: 'merge' });
  assert.equal(a.id, b.id);
  assert.deepEqual(b.tags.sort(), ['a', 'b']);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: distinct value under same key keeps both', () => {
  const root = tmp();
  const m = new Memory(root);
  m.add('p1', { key: 'k', value: '1', type: 'fact' });
  m.add('p1', { key: 'k', value: '2', type: 'fact' });
  assert.equal(m.list('p1').length, 2);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: update modifies the record in place', () => {
  const root = tmp();
  const m = new Memory(root);
  const a = m.add('p1', { key: 'k', value: '1', type: 'fact', confidence: 0.5 });
  const updated = m.update(a.id, 'p1', { confidence: 0.9 });
  assert.equal(updated.confidence, 0.9);
  const got = m.get(a.id, 'p1');
  assert.equal(got.confidence, 0.9);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: delete removes a record', () => {
  const root = tmp();
  const m = new Memory(root);
  const a = m.add('p1', { key: 'k', value: 'v', type: 'fact' });
  assert.equal(m.delete(a.id, 'p1'), true);
  assert.equal(m.get(a.id, 'p1'), null);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: retention drops expired records on read', () => {
  const root = tmp();
  const m = new Memory(root);
  m.add('p1', { key: 'k', value: 'v', type: 'fact', ttlMs: 1, ts: new Date(Date.now() - 100).toISOString() });
  assert.equal(m.list('p1').length, 0, 'expired record was returned');
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: search ranks key > value > tag', async () => {
  const root = tmp();
  const m = new Memory(root);
  m.add('p1', { key: 'k1', value: 'unrelated', tags: ['idor'], type: 'fact' });
  m.add('p1', { key: 'k2', value: 'idor in /api', tags: [], type: 'fact' });
  m.add('p1', { key: 'idor_target', value: 'x', tags: [], type: 'fact' });
  const r = await m.search('idor', 'p1');
  assert.equal(r.length, 3);
  assert.equal(r[0].key, 'idor_target', 'key match should rank first');
  assert.equal(r[1].key, 'k2', 'value match should rank second');
  assert.equal(r[2].key, 'k1', 'tag match should rank last');
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: secret-shaped value is redacted before write', () => {
  const root = tmp();
  const m = new Memory(root);
  const r = m.add('p1', { key: 'k', value: 'api_key=sk-abcdefghijklmnopqrst', type: 'fact' });
  assert.match(r.value, /\[REDACTED\]/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: malformed record is quarantined, not loaded', () => {
  const root = tmp();
  fs.writeFileSync(path.join(root, 'p1.json'), JSON.stringify([
    { id: 'm_a', projectId: 'p1', key: 'good', value: 'v', ts: 't', type: 'fact' },
    { broken: true },  // invalid: missing fields
  ]));
  const m = new Memory(root);
  assert.equal(m.list('p1').length, 1);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: checkpoint save/load', () => {
  const root = tmp();
  const m = new Memory(root);
  m.saveCheckpoint('p1', {
    objective: 'audit staging',
    completed: ['create task', 'classify'],
    pending: ['run headers check'],
    decisions: ['use offline provider for tests'],
    errors: [],
    nextActions: ['run header check', 'write report'],
  });
  const cp = m.loadCheckpoint('p1');
  assert.equal(cp.objective, 'audit staging');
  assert.equal(cp.completed.length, 2);
  assert.equal(cp.pending[0], 'run headers check');
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: assembleContext splits verified/assumption/unresolved', async () => {
  const root = tmp();
  const m = new Memory(root);
  m.add('p1', { key: 'hsts_required', value: 'true', type: 'fact' });
  m.add('p1', { key: 'cms_may_redirect', value: '?next=', type: 'assumption' });
  m.add('p1', { key: 'is_there_a_waf', value: 'unknown', type: 'unresolved' });
  const ctx = await m.assembleContext({ projectId: 'p1' });
  assert.equal(ctx.verified.length, 1);
  assert.equal(ctx.assumption.length, 1);
  assert.equal(ctx.unresolved.length, 1);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: assembleContext scopes to a task', async () => {
  const root = tmp();
  const m = new Memory(root);
  m.add('p1', { key: 'a', value: 'project-wide', type: 'fact' }, { taskId: null });
  m.add('p1', { key: 'b', value: 'task-scoped', type: 'fact' }, { taskId: 't_1' });
  const ctx = await m.assembleContext({ projectId: 'p1', taskId: 't_1' });
  assert.equal(ctx.taskScoped.length, 1);
  assert.equal(ctx.taskScoped[0].key, 'b');
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: persists across new Memory instance', () => {
  const root = tmp();
  const m1 = new Memory(root);
  m1.add('p1', { key: 'k', value: 'v', type: 'fact' });
  const m2 = new Memory(root);
  assert.equal(m2.list('p1').length, 1);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: list rejects unknown type at write time (validate guards)', () => {
  const root = tmp();
  const m = new Memory(root);
  assert.throws(() => m.add('p1', { key: 'k', value: 'v', type: 'nope' }), /unknown memory type/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory2: required schema fields are exposed', () => {
  assert.ok(MEMORY_TYPES.has('fact'));
  assert.ok(MEMORY_TYPES.has('decision'));
  assert.ok(MEMORY_TYPES.has('assumption'));
  assert.ok(MEMORY_TYPES.has('unresolved'));
  assert.ok(MEMORY_TYPES.has('evidence'));
  assert.ok(MEMORY_TYPES.has('preference'));
});
