'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Storage } = require('../aegis/storage');
const { Task } = require('../aegis/task');

function tmpRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-storage-'));
}

test('storage: put and get round-trip', () => {
  const root = tmpRoot();
  const s = new Storage(root);
  const t = new Task({ title: 'x', role: 'coding' });
  t.transition('READY');
  s.put(t);
  const got = s.get(t.id);
  assert.equal(got.id, t.id);
  assert.equal(got.state, t.state);
  fs.rmSync(root, { recursive: true, force: true });
});

test('storage: list returns every task', () => {
  const root = tmpRoot();
  const s = new Storage(root);
  s.put(new Task({ title: 'a' }));
  s.put(new Task({ title: 'b' }));
  s.put(new Task({ title: 'c' }));
  assert.equal(s.list().length, 3);
  fs.rmSync(root, { recursive: true, force: true });
});

test('storage: remove deletes file and index entry', () => {
  const root = tmpRoot();
  const s = new Storage(root);
  const t = new Task({ title: 'a' });
  s.put(t);
  s.remove(t.id);
  assert.equal(s.get(t.id), null);
  assert.equal(s.list().length, 0);
  fs.rmSync(root, { recursive: true, force: true });
});

test('storage: index survives a new Storage instance', () => {
  const root = tmpRoot();
  const s1 = new Storage(root);
  const t = new Task({ title: 'persist' });
  s1.put(t);
  const s2 = new Storage(root);
  const got = s2.get(t.id);
  assert.ok(got);
  assert.equal(got.title, 'persist');
  fs.rmSync(root, { recursive: true, force: true });
});

test('storage: corrupted index is recovered (not crash)', () => {
  const root = tmpRoot();
  fs.writeFileSync(path.join(root, '_index.json'), '{ not valid json');
  const s = new Storage(root);
  assert.equal(s.list().length, 0);
  fs.rmSync(root, { recursive: true, force: true });
});
