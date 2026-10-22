'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Memory } = require('../aegis/memory');

function tmpRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-memory-'));
}

test('memory: add and search', async () => {
  const root = tmpRoot();
  const m = new Memory(root);
  m.add('p1', { key: 'scope', value: 'https://127.0.0.1:8000' });
  m.add('p1', { key: 'todo', value: 'check hsts', tags: ['header', 'tls'] });
  const r = await m.search('hsts', 'p1');
  assert.equal(r.length, 1);
  assert.equal(r[0].key, 'todo');
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory: empty project returns no matches', async () => {
  const root = tmpRoot();
  const m = new Memory(root);
  const r = await m.search('anything', 'p2');
  assert.deepEqual(r, []);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory: missing query rejected', async () => {
  const root = tmpRoot();
  const m = new Memory(root);
  await assert.rejects(() => m.search('', 'p3'), /query required/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('memory: add rejects missing key', () => {
  const root = tmpRoot();
  const m = new Memory(root);
  assert.throws(() => m.add('p1', { value: 'x' }), /key is required/);
  fs.rmSync(root, { recursive: true, force: true });
});
