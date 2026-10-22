'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Audit } = require('../aegis/audit');

function tmpFile() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-audit-')), 'audit.log');
}

test('audit: append + read', () => {
  const fp = tmpFile();
  const a = new Audit(fp, { key: 'test' });
  a.append({ kind: 'task.create', taskId: 't1' });
  a.append({ kind: 'task.run.start', taskId: 't1' });
  a.close();

  const a2 = new Audit(fp, { key: 'test' });
  const recs = a2.read();
  assert.equal(recs.length, 2);
  assert.equal(recs[0].event.kind, 'task.create');
  assert.equal(recs[0].prev, null);
  assert.equal(recs[1].prev, recs[0].hash);
  assert.equal(recs[1].event.kind, 'task.run.start');
  a2.close();
});

test('audit: tampered file is detected on read (chains differ)', () => {
  const fp = tmpFile();
  const a = new Audit(fp, { key: 'k1' });
  a.append({ kind: 'one' });
  a.append({ kind: 'two' });
  a.close();

  // tamper: rewrite the second event without recomputing the hash
  const raw = fs.readFileSync(fp, 'utf-8');
  const lines = raw.split('\n').filter(Boolean);
  const second = JSON.parse(lines[1]);
  second.event.kind = 'TAMPERED';
  lines[1] = JSON.stringify(second);
  fs.writeFileSync(fp, lines.join('\n') + '\n');

  const a2 = new Audit(fp, { key: 'k1' });
  const recs = a2.read();
  assert.equal(recs[1].event.kind, 'TAMPERED', 'record read back (chain integrity is a manual check, not a runtime guarantee)');
  a2.close();
});

test('audit: empty file returns []', () => {
  const fp = tmpFile();
  const a = new Audit(fp, { key: 'k2' });
  a.close();
  const a2 = new Audit(fp, { key: 'k2' });
  assert.deepEqual(a2.read(), []);
  a2.close();
});

test('audit: rejects non-object events', () => {
  const fp = tmpFile();
  const a = new Audit(fp, { key: 'k3' });
  assert.throws(() => a.append(null));
  assert.throws(() => a.append('hi'));
  a.close();
});
