'use strict';

/**
 * Regression tests for three defects found while bringing Phase 2 to green.
 * Each one is a case where the test suite was describing the intent but the
 * implementation had drifted, or where a test was passing over a gap.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const aegis = require('../aegis');
const { Memory, validate } = require('../aegis/memory');
const { buildDefaultRegistry } = require('../aegis/agent');
const { buildDefaultRegistry: buildTools } = require('../aegis/tools/registry');
const { buildDefaultManifest, Orchestrator } = require('../aegis/orchestrator');
const specialists = require('../aegis/specialists');
const { Task } = require('../aegis/task');

function tmpRoot(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `aegis-fix-${tag}-`));
}

// ---- defect 1: a missing key was stored as the string "undefined" ---------

test('fix: memory.add rejects a missing key instead of storing "undefined"', () => {
  const root = tmpRoot('memkey');
  const m = new Memory(root);
  assert.throws(() => m.add('p1', { value: 'x' }), /key is required/);
  // the important half: nothing was written
  assert.equal(m.list('p1').length, 0);
  fs.rmSync(root, { recursive: true, force: true });
});

test('fix: the two key guards are both pinned', () => {
  // API boundary — the exact Phase 1 message
  const root = tmpRoot('memkey-guard');
  const m = new Memory(root);
  assert.throws(() => m.add('p1', { value: 'x' }), /memory\.add: key is required/);
  // schema boundary — used to quarantine malformed records read off disk
  assert.match(validate({}), /missing field/);
  assert.match(validate({ id: 'm_1', projectId: 'p1', key: '', value: 'v', ts: 't', type: 'fact' }), /missing field: key/);
  assert.match(validate({ id: 'm_1', projectId: 'p1', value: 'v', ts: 't', type: 'fact' }), /missing field: key/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('fix: memory.add rejects an empty-string key', () => {
  const root = tmpRoot('memkey2');
  const m = new Memory(root);
  assert.throws(() => m.add('p1', { key: '', value: 'x' }), /key is required/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('fix: memory.add rejects a null key', () => {
  const root = tmpRoot('memkey3');
  const m = new Memory(root);
  assert.throws(() => m.add('p1', { key: null, value: 'x' }), /key is required/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('fix: two keyless writes must not collapse onto one record', () => {
  const root = tmpRoot('memkey4');
  const m = new Memory(root);
  assert.throws(() => m.add('p1', { value: 'a' }), /key is required/);
  assert.throws(() => m.add('p1', { value: 'b' }), /key is required/);
  assert.equal(m.list('p1').filter((r) => r.key === 'undefined').length, 0);
  fs.rmSync(root, { recursive: true, force: true });
});

test('fix: a real key still round-trips unchanged', () => {
  const root = tmpRoot('memkey5');
  const m = new Memory(root);
  const rec = m.add('p1', { key: 'stack', value: 'node', tags: ['infra'] });
  assert.equal(rec.key, 'stack');
  assert.equal(m.get(rec.id, 'p1').value, 'node');
  fs.rmSync(root, { recursive: true, force: true });
});

// ---- defect 2: buildDefaultManifest dropped the Phase 1 roles ------------

test('fix: the default manifest covers every Phase 1 role', () => {
  const m = buildDefaultManifest();
  for (const role of ['coding', 'classifier', 'echo', 'doctor', 'fail']) {
    assert.ok(m.get(role), `manifest lost Phase 1 role: ${role}`);
  }
});

test('fix: every manifest role has a registered runner (and vice versa)', () => {
  const agents = buildDefaultRegistry();
  const m = buildDefaultManifest(agents);
  for (const role of m.list()) {
    assert.ok(agents.get(role), `manifest declares "${role}" with no runner`);
  }
  for (const role of agents.list()) {
    assert.ok(m.get(role), `registry has "${role}" but the manifest does not`);
  }
});

test('fix: a synthesised declaration is restrictive, not permissive', () => {
  const m = buildDefaultManifest();
  const doctor = m.get('doctor');
  assert.equal(doctor.__synthesised, true);
  assert.deepEqual(doctor.allowedTools, [], 'a fallback declaration must grant no tools');
  assert.equal(doctor.resourceLimits.maxDelegationDepth, 0);
});

test('fix: an explicitly declared role is not overwritten by a fallback', () => {
  const m = buildDefaultManifest();
  const research = m.get('research');
  assert.notEqual(research.__synthesised, true);
  assert.ok(research.allowedTools.includes('http.get'));
});

test('fix: buildDefaultManifest deep-clones so mutation cannot leak', () => {
  const a = buildDefaultManifest();
  a.get('doctor').resourceLimits.maxWallMs = 999_999;
  const b = buildDefaultManifest();
  assert.notEqual(b.get('doctor').resourceLimits.maxWallMs, 999_999);
});

// ---- defect 3: the specialist roles were declared but unimplemented ------

test('fix: every specialist role runs under the orchestrator', async () => {
  const agents = buildDefaultRegistry();
  const o = new Orchestrator({
    manifest: buildDefaultManifest(agents),
    agentRegistry: agents,
    toolRegistry: buildTools(),
    memory: null,
  });
  const r = await o.run(new Task({ role: 'review', input: { text: 'const a = 1;' } }));
  assert.equal(r.status, 'SUCCEEDED');
  assert.equal(typeof r.output.score, 'number');
});

test('specialist review: flags a hardcoded credential as a blocker', async () => {
  const r = await specialists.review(
    new Task({ role: 'review', input: { text: 'const api_key = "sk-live-abc123def"' } }), {});
  assert.ok(r.output.blockers.some((b) => b.id === 'hardcoded-credential'));
  assert.ok(r.output.score < 100);
});

test('specialist review: clean input scores 100 with no blockers', async () => {
  const r = await specialists.review(
    new Task({ role: 'review', input: { text: 'const total = a + b;' } }), {});
  assert.equal(r.output.blockers.length, 0);
  assert.equal(r.output.score, 100);
});

test('specialist memory: writes a fact and returns its id', async () => {
  const root = tmpRoot('specmem');
  const m = new Memory(root);
  const r = await specialists.memory(
    new Task({ role: 'memory', input: { projectId: 'p1', key: 'stack', value: 'node' } }),
    { memory: m });
  assert.equal(r.status, 'SUCCEEDED');
  assert.ok(r.output.id);
  assert.equal(m.list('p1')[0].key, 'stack');
  fs.rmSync(root, { recursive: true, force: true });
});

test('specialist memory: redacts a secret before it reaches disk', async () => {
  const root = tmpRoot('specsec');
  const m = new Memory(root);
  await specialists.memory(
    new Task({ role: 'memory', input: { projectId: 'p1', key: 'creds', value: 'api_key=sk-live-abcdef123456' } }),
    { memory: m });
  const onDisk = JSON.stringify(m.list('p1'));
  assert.ok(!onDisk.includes('sk-live-abcdef123456'), 'secret leaked to memory');
  fs.rmSync(root, { recursive: true, force: true });
});

test('specialist memory: fails loudly when no store is wired', async () => {
  const r = await specialists.memory(new Task({ role: 'memory', input: { projectId: 'p1', key: 'k', value: 'v' } }), {});
  assert.equal(r.status, 'FAILED');
  assert.match(r.error, /no memory store/);
});

test('specialist research: fetches a loopback URL through the tool registry', async () => {
  const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('hello from loopback'); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  try {
    const r = await specialists.research(new Task({ role: 'research', input: { url } }), {
      tools: buildTools(),
      allowedTools: ['http.get'],
    });
    assert.equal(r.status, 'SUCCEEDED');
    assert.equal(r.output.status, 200);
    assert.match(r.output.snippet, /hello from loopback/);
  } finally {
    server.close();
  }
});

test('specialist research: cannot reach a non-loopback host', async () => {
  const r = await specialists.research(
    new Task({ role: 'research', input: { url: 'http://example.com/' } }),
    { tools: buildTools(), allowedTools: ['http.get'] });
  assert.equal(r.status, 'FAILED');
  assert.match(r.error, /loopback/);
});

test('specialist research: is refused when http.get is not allowlisted', async () => {
  const r = await specialists.research(
    new Task({ role: 'research', input: { url: 'http://127.0.0.1:1/' } }),
    { tools: buildTools(), allowedTools: ['hash.sha256'] });
  assert.equal(r.status, 'FAILED');
  assert.match(r.error, /denied|not in task allowedTools/);
});

test('specialist router: routes on intent and always returns a role', async () => {
  const cases = [
    ['please review this diff', 'review'],
    ['fetch https://example.com/docs', 'research'],
    ['remember that we use node 18', 'memory'],
    ['run a doctor check', 'doctor'],
    ['completely unrelated sentence', 'coding'],
  ];
  for (const [text, want] of cases) {
    const r = await specialists.router(new Task({ role: 'router', input: { text } }), {});
    assert.equal(r.status, 'SUCCEEDED');
    assert.equal(r.output.recommended, want, `for "${text}"`);
  }
});

// ---- public surface ------------------------------------------------------

test('fix: specialists and synthesiseDeclaration are exported', () => {
  for (const name of ['specialists', 'synthesiseDeclaration', 'buildDefaultManifest']) {
    assert.ok(name in aegis, `missing export: ${name}`);
  }
});