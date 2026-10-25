'use strict';

/**
 * Phase 2.2 regression tests.
 *
 * One test per confirmed defect, named with the finding id from
 * `PHASE22_SECURITY_AND_RELIABILITY_REPORT.md`. Each test pins the
 * behaviour that was wrong before the fix, so a regression is reported
 * against the finding it belongs to rather than as an anonymous failure.
 *
 * These are *minimal* regression cases: each one reproduces exactly the
 * input that exposed the defect. The broader randomised coverage lives in
 * `test/adversarial.test.js`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const { Storage } = require('../aegis/storage');
const { Task } = require('../aegis/task');
const { Memory } = require('../aegis/memory');
const { Checkpoint, CheckpointStore } = require('../aegis/recovery');
const { BudgetManager } = require('../aegis/usage');
const { ToolRegistry, Tool, buildDefaultRegistry } = require('../aegis/tools/registry');
const { HttpProvider, extractTextAndUsage } = require('../aegis/providers/http');
const { Audit } = require('../aegis/audit');
const { redactString } = require('../aegis/redact');
const { Orchestrator, buildDefaultManifest } = require('../aegis/orchestrator');
const { isSafeIdentifier } = require('../aegis/paths');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

test('P22-01: a task id of "__proto__" is stored, listed and retrievable', () => {
  const root = tmpDir('aegis-p22-01-');
  try {
    const store = new Storage(path.join(root, 'state'));
    store.put(new Task({ id: '__proto__', title: 'proto task' }));

    assert.ok(
      store.list().some((t) => t.id === '__proto__'),
      'the task was written to disk but is missing from list()',
    );
    assert.equal(store.get('__proto__').title, 'proto task');
    // The index map must not have had its prototype replaced.
    assert.equal(Object.getPrototypeOf(store._index.tasks), null);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('P22-02: two ids that resolve to the same file cannot overwrite each other', () => {
  const root = tmpDir('aegis-p22-02-');
  try {
    const store = new Storage(path.join(root, 'state'));
    store.put(new Task({ id: 'Alpha', title: 'upper' }));
    assert.throws(
      () => store.put(new Task({ id: 'alpha', title: 'lower' })),
      (err) => err.code === 'TASK_ID_CONFLICT',
      'the second task silently overwrote the first',
    );
    assert.equal(store.get('Alpha').title, 'upper');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('P22-03: a task id cannot resolve to the task index file', () => {
  const root = tmpDir('aegis-p22-03-');
  try {
    const store = new Storage(path.join(root, 'state'));
    store.put(new Task({ id: 'ordinary', title: 'fine' }));
    assert.throws(
      () => store.put(new Task({ id: '_index', title: 'clobber' })),
      (err) => err.code === 'INVALID_ID',
    );
    const reloaded = new Storage(path.join(root, 'state'));
    assert.ok(reloaded.list().some((t) => t.id === 'ordinary'), 'the index was damaged');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('P22-04: a task file is never served under a different task id', () => {
  const root = tmpDir('aegis-p22-04-');
  try {
    const stateDir = path.join(root, 'state');
    const store = new Storage(stateDir);
    store.put(new Task({ id: 'real', title: 'real task' }));
    // Overwrite the file with a record for a different id.
    fs.writeFileSync(path.join(stateDir, 'real.json'), JSON.stringify({ id: 'other', title: 'other' }));
    assert.equal(store.get('real'), null, 'a record for another task was served');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('P22-05: identifiers that cannot form a filename on Windows are refused', () => {
  // These characters are legal on POSIX but not on Windows, so accepting
  // them made the same id behave differently on each platform.
  for (const id of ['a>b', 'a<b', 'a|b', 'a*b', 'a?b', 'a"b', 'CON', 'con', 'nul', 'COM1', 'a\tb']) {
    assert.equal(isSafeIdentifier(id), false, `the identifier ${JSON.stringify(id)} was accepted`);
  }
  // Ordinary identifiers must still work.
  for (const id of ['task-1', 'task_1', 'Task.1', 'a'.repeat(200)]) {
    assert.equal(isSafeIdentifier(id), true, `the identifier ${JSON.stringify(id)} was refused`);
  }
});

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

test('P22-06: a refused attempt does not charge the global budget', () => {
  const manager = new BudgetManager({ maxAttempts: 100 });
  manager.forTask('t1', { maxAttempts: 2 });
  manager.record('t1', { input: 0, output: 0, tokens: null, attempt: true });
  manager.record('t1', { input: 0, output: 0, tokens: null, attempt: true });
  const globalBefore = manager.global.attempts;
  const taskBefore = manager.forTask('t1').attempts;

  assert.throws(
    () => manager.record('t1', { input: 0, output: 0, tokens: null, attempt: true }),
    (err) => err.code === 'BUDGET_EXCEEDED',
  );
  assert.equal(manager.global.attempts, globalBefore, 'the global budget was charged for a refused attempt');
  assert.equal(manager.forTask('t1').attempts, taskBefore);
});

// ---------------------------------------------------------------------------
// Checkpoints and recovery
// ---------------------------------------------------------------------------

test('P22-07: a checkpoint with a non-array collection is rejected', () => {
  const dir = tmpDir('aegis-p22-07-');
  try {
    const store = new CheckpointStore(dir);
    fs.writeFileSync(
      path.join(dir, 'bad.checkpoint.json'),
      JSON.stringify({ taskId: 'bad', completed: 'not-an-array', pending: 'not-an-array' }),
    );
    assert.equal(store.load('bad'), null, 'a malformed checkpoint was accepted');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('P22-08: a checkpoint with an unsupported version is rejected', () => {
  const dir = tmpDir('aegis-p22-08-');
  try {
    const store = new CheckpointStore(dir);
    fs.writeFileSync(
      path.join(dir, 'v99.checkpoint.json'),
      JSON.stringify({ taskId: 'v99', completed: [], pending: [], version: 999 }),
    );
    assert.equal(store.load('v99'), null, 'an unsupported checkpoint version was accepted');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('P22-09: a checkpoint whose entries are not objects is rejected', () => {
  const dir = tmpDir('aegis-p22-09-');
  try {
    const store = new CheckpointStore(dir);
    fs.writeFileSync(
      path.join(dir, 'nulls.checkpoint.json'),
      JSON.stringify({ taskId: 'nulls', completed: [null], pending: [42] }),
    );
    const cp = store.load('nulls');
    assert.equal(cp, null, 'a checkpoint with a null entry was accepted');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('P22-09b: a checkpoint that loads can always be used', () => {
  const dir = tmpDir('aegis-p22-09b-');
  try {
    const store = new CheckpointStore(dir);
    fs.writeFileSync(
      path.join(dir, 'ok.checkpoint.json'),
      JSON.stringify({ taskId: 'ok', completed: [{ seq: 1, name: 's', idempotencyKey: 'k' }], pending: [] }),
    );
    const cp = store.load('ok');
    assert.ok(cp);
    assert.doesNotThrow(() => cp.markCompleted({ seq: 2, name: 's2', idempotencyKey: 'k2' }));
    assert.doesNotThrow(() => JSON.stringify(cp.toJSON()));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

test('P22-10: a memory write leaves the previous records intact', () => {
  const dir = tmpDir('aegis-p22-10-');
  try {
    const mem = new Memory(dir);
    mem.add('p', { key: 'k1', value: 'v1' });
    mem.add('p', { key: 'k2', value: 'v2' });
    mem.add('p', { key: 'k3', value: 'v3' });
    const records = mem.list('p');
    assert.equal(records.length, 3);
    // The file must be valid JSON after every write.
    const raw = JSON.parse(fs.readFileSync(path.join(dir, 'p.json'), 'utf-8'));
    assert.equal(raw.length, 3);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('P22-11: a task context never contains another task\'s records', async () => {
  const dir = tmpDir('aegis-p22-11-');
  try {
    const mem = new Memory(dir);
    mem.add('p', { key: 'shared', value: 'project wide' }, { taskId: null });
    mem.add('p', { key: 'a-only', value: 'A' }, { taskId: 'task-A' });
    mem.add('p', { key: 'b-only', value: 'B' }, { taskId: 'task-B' });

    const ctx = await mem.assembleContext({ projectId: 'p', taskId: 'task-A' });
    const keys = ctx.verified.map((r) => r.key);
    assert.ok(keys.includes('shared'), 'a project-wide record was dropped');
    assert.ok(keys.includes('a-only'), "the task's own record was dropped");
    assert.ok(!keys.includes('b-only'), "another task's record leaked into the context");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Tool permissions
// ---------------------------------------------------------------------------

test('P22-12: an allowlist that is not a list allows nothing', async () => {
  let executed = false;
  const registry = new ToolRegistry();
  registry.register(new Tool({
    name: 'echo',
    purpose: 'probe',
    riskLevel: 'read',
    run: async () => { executed = true; return 'ran'; },
  }));
  // 'xechox'.includes('echo') is true, so a string allowlist used to let the
  // tool through.
  await assert.rejects(
    () => registry.run('echo', { value: 'x' }, { allowedTools: 'xechox' }),
    (err) => err.code === 'TOOL_DENIED',
  );
  assert.equal(executed, false);
});

test('P22-13: a tool input that violates its own schema is refused', async () => {
  let executed = false;
  const registry = new ToolRegistry();
  registry.register(new Tool({
    name: 'hash.sha256',
    purpose: 'probe',
    riskLevel: 'read',
    inputSchema: { type: 'object', properties: { value: { type: 'string' } }, required: ['value'] },
    run: async (input) => { executed = true; return String(input.value); },
  }));
  await assert.rejects(
    () => registry.run('hash.sha256', {}, { allowedTools: ['hash.sha256'] }),
    (err) => err.code === 'TOOL_INPUT_INVALID',
  );
  assert.equal(executed, false, 'the tool ran with an input its schema forbids');
});

test('P22-14: an unknown risk ceiling is refused instead of granting the highest', async () => {
  let executed = false;
  const registry = new ToolRegistry();
  registry.register(new Tool({
    name: 'danger',
    purpose: 'probe',
    riskLevel: 'destructive',
    run: async () => { executed = true; return 'ran'; },
  }));
  await assert.rejects(
    () => registry.run('danger', {}, { allowedTools: ['danger'], maxRiskLevel: 'bogus' }),
    (err) => err.code === 'TOOL_DENIED',
  );
  assert.equal(executed, false);
});

test('P22-15: a destructive tool does not run under the default ceiling', async () => {
  let executed = false;
  const registry = new ToolRegistry();
  registry.register(new Tool({
    name: 'danger',
    purpose: 'probe',
    riskLevel: 'destructive',
    run: async () => { executed = true; return 'ran'; },
  }));
  await assert.rejects(
    () => registry.run('danger', {}, { allowedTools: ['danger'] }),
    (err) => err.code === 'TOOL_DENIED',
  );
  assert.equal(executed, false);
});

test('P22-16: fs.read checks the size of the file it actually reads', async () => {
  const dir = tmpDir('aegis-p22-16-');
  const fsModule = require('node:fs');
  try {
    const small = path.join(dir, 'small.txt');
    const big = path.join(dir, 'big.txt');
    fs.writeFileSync(small, 'x'.repeat(16));
    fs.writeFileSync(big, 'y'.repeat(2 * 1024 * 1024));

    // Simulate the attacker winning the race: the path is checked while it
    // still resolves to the small file, and resolves to the oversized file
    // by the time the bytes are read. Before the fix, the size was taken
    // from `statSync(path)` and the bytes came from `realpath(path)`, so
    // the 1 MiB ceiling was checked against a file that was never read.
    const realpathSync = fsModule.realpathSync;
    fsModule.realpathSync = function patched(p, ...rest) {
      if (path.resolve(String(p)) === path.resolve(small)) return big;
      return realpathSync.call(this, p, ...rest);
    };

    try {
      const registry = buildDefaultRegistry();
      await assert.rejects(
        () => registry.run('fs.read', { path: small }, {
          allowedTools: ['fs.read'],
          allowedRoots: [dir],
        }),
        // The size is now taken from the open descriptor, so the file that
        // is actually read is the file that was measured.
        (err) => err.code === 'TOOL_OUTPUT_TOO_LARGE',
      );
    } finally {
      fsModule.realpathSync = realpathSync;
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('P22-24: a failed audit append is counted, not swallowed silently', async () => {
  const registry = new ToolRegistry();
  registry.register(new Tool({
    name: 'ok',
    purpose: 'probe',
    riskLevel: 'read',
    run: async () => 'fine',
  }));
  const before = registry.auditFailures;
  await registry.run('ok', {}, {
    allowedTools: ['ok'],
    audit: { append() { throw new Error('audit disk full'); } },
  });
  assert.ok(registry.auditFailures > before, 'the audit failure was not counted');
});

test('P22-26: a credential in a tool input is redacted before it reaches the audit log', async () => {
  const events = [];
  const registry = new ToolRegistry();
  registry.register(new Tool({
    name: 'ok',
    purpose: 'probe',
    riskLevel: 'read',
    run: async () => 'fine',
  }));
  await registry.run('ok', { value: 'api_key: super-secret-value' }, {
    allowedTools: ['ok'],
    audit: { append: (e) => events.push(e) },
  });
  const start = events.find((e) => e.kind === 'tool.call.start');
  assert.ok(start, 'no start event was recorded');
  assert.ok(!start.inputSummary.includes('super-secret-value'), 'the secret reached the audit log');
  assert.match(start.inputSummary, /\[REDACTED[^\]]*\]/);
});

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

test('P22-17: usage that the server did not report is not recorded as a measured zero', () => {
  const out = extractTextAndUsage({ usage: {} }, '{}');
  assert.equal(out.usage.reported, false);
  assert.equal(out.usage.total, 0);
});

test('P22-18: a non-numeric usage counter never becomes NaN', () => {
  const out = extractTextAndUsage({ usage: { prompt_tokens: 'abc', completion_tokens: 'def' } }, '{}');
  assert.ok(Number.isFinite(out.usage.input));
  assert.ok(Number.isFinite(out.usage.output));
  assert.ok(Number.isFinite(out.usage.total));
  assert.equal(out.usage.reported, false, 'an unusable counter was reported as measured');
});

test('P22-19: a redirect response is an error, not model output', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(302, { location: 'http://127.0.0.1:1/elsewhere' });
    res.end('REDIRECT BODY');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  try {
    const p = new HttpProvider({ baseUrl: `http://127.0.0.1:${port}/` });
    await assert.rejects(
      () => p.complete({ messages: [{ role: 'user', content: 'hi' }] }),
      (err) => /redirect/i.test(err.message),
    );
  } finally {
    server.close();
  }
});

test('P22-20: a provider URL with a non-http scheme is refused', () => {
  assert.throws(
    () => new HttpProvider({ baseUrl: 'file:///etc/passwd' }),
    /unsupported protocol/,
  );
});

test('P22-21: a slow response is cut off by a total deadline', async () => {
  // The server sends one byte at a time, so the socket is never idle for
  // longer than the socket timeout. Only a total deadline ends this.
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    let sent = 0;
    const timer = setInterval(() => {
      sent += 1;
      res.write('x');
      if (sent > 50) { clearInterval(timer); res.end(); }
    }, 20);
    res.on('close', () => clearInterval(timer));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  try {
    const p = new HttpProvider({ baseUrl: `http://127.0.0.1:${port}/`, timeoutMs: 200 });
    await assert.rejects(
      () => p.complete({ messages: [{ role: 'user', content: 'hi' }] }),
      (err) => /timeout/i.test(err.message),
    );
  } finally {
    server.close();
  }
});

test('P22-22: an aborted request is stopped and reported', async () => {
  const server = http.createServer(() => { /* never responds */ });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const controller = new AbortController();
  try {
    const p = new HttpProvider({ baseUrl: `http://127.0.0.1:${port}/`, timeoutMs: 5000 });
    const pending = p.complete({ messages: [{ role: 'user', content: 'hi' }], signal: controller.signal });
    setTimeout(() => controller.abort(), 30);
    await assert.rejects(pending, (err) => err.code === 'ABORTED');
  } finally {
    server.close();
  }
});

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

test('P22-23: a nested output that violates its declared schema is refused', async () => {
  const manifest = buildDefaultManifest();
  const orchestrator = new Orchestrator({
    manifest,
    agentRegistry: {
      get: () => ({
        run: async () => ({
          status: 'SUCCEEDED',
          output: { score: 'NOT-A-NUMBER', summary: 42, blockers: 'not-an-array', nits: [] },
          evidence: [],
        }),
      }),
    },
    toolRegistry: new ToolRegistry(),
  });
  await assert.rejects(
    () => orchestrator.run(new Task({ id: 't1', role: 'review' })),
    (err) => err.code === 'SCHEMA_VIOLATION',
  );
});

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

test('P22-25: common credential shapes are redacted', () => {
  const cases = [
    ['AWS access key', 'AKIAIOSFODNN7EXAMPLE'],
    ['GitHub token', 'ghp_' + 'a'.repeat(36)],
    ['Slack token', 'xoxb-123456789012-abcdefghijkl'],
    ['JWT', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abcdefghijkl'],
    ['private key', '-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----'],
    ['connection string', 'postgres://admin:hunter2@db.internal:5432/app'],
    ['basic auth', 'Authorization: Basic YWRtaW46aHVudGVyMg=='],
  ];
  for (const [name, secret] of cases) {
    const redacted = redactString(secret);
    assert.match(redacted, /\[REDACTED[^\]]*\]/, `the ${name} was not redacted`);
  }
});

test('P22-25b: the labelled secret forms are still redacted', () => {
  for (const secret of ['api_key: abc123', 'password=hunter2', 'client_secret: abc123', 'x-api-key: abc123']) {
    assert.match(redactString(secret), /\[REDACTED[^\]]*\]/, `not redacted: ${secret}`);
  }
});

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

test('P22-27: the audit chain key is not a published constant', () => {
  const dir = tmpDir('aegis-p22-27-');
  try {
    const fp = path.join(dir, 'audit.log');
    const a = new Audit(fp);
    const b = new Audit(fp);
    assert.notEqual(a.key, 'aegis-default-audit-key');
    // Two instances without an explicit key must not share a key.
    assert.notEqual(a.key, b.key, 'two audit instances shared a chain key');
    a.close();
    b.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('P22-28: the audit chain can be verified and detects tampering', () => {
  const dir = tmpDir('aegis-p22-28-');
  try {
    const fp = path.join(dir, 'audit.log');
    const a = new Audit(fp, { key: 'unit-test-key' });
    a.append({ kind: 'one' });
    a.append({ kind: 'two' });
    a.close();

    const clean = new Audit(fp, { key: 'unit-test-key' });
    const before = clean.verify();
    assert.equal(before.ok, true, `the untouched chain failed verification: ${before.errors.join('; ')}`);
    assert.equal(before.checked, 2);
    clean.close();

    // Tamper with the second record without recomputing its hash.
    const lines = fs.readFileSync(fp, 'utf-8').split('\n').filter(Boolean);
    const second = JSON.parse(lines[1]);
    second.event.kind = 'TAMPERED';
    lines[1] = JSON.stringify(second);
    fs.writeFileSync(fp, lines.join('\n') + '\n');

    const dirty = new Audit(fp, { key: 'unit-test-key' });
    const after = dirty.verify();
    assert.equal(after.ok, false, 'a tampered chain verified as intact');
    assert.ok(after.errors.length > 0);
    dirty.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

test('P22-29: a second writer over the same state directory does not lose the first writer\'s tasks', () => {
  const dir = tmpDir('aegis-p22-29-');
  try {
    // Two independent stores over one directory — the shape of two AEGIS
    // processes, or two Storage objects in one process.
    const a = new Storage(dir);
    const b = new Storage(dir);

    a.put(new Task({ id: 'taskA', role: 'coding' }));
    b.put(new Task({ id: 'taskB', role: 'review' }));

    // Before the fix, writing taskB rewrote the index from B's stale
    // in-memory snapshot, which knew nothing about taskA. taskA.json
    // survived on disk but disappeared from the index — silent data loss.
    const index = JSON.parse(fs.readFileSync(path.join(dir, '_index.json'), 'utf-8'));
    assert.deepEqual(Object.keys(index.tasks).sort(), ['taskA', 'taskB']);
    assert.ok(a.get('taskA'), 'taskA vanished from the store');
    assert.ok(b.get('taskB'), 'taskB is missing from the store');
    assert.deepEqual(a.list().map((t) => t.id).sort(), ['taskA', 'taskB']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('P22-29b: a removal by one writer is not resurrected by another writer', () => {
  const dir = tmpDir('aegis-p22-29b-');
  try {
    const a = new Storage(dir);
    const b = new Storage(dir);
    a.put(new Task({ id: 'doomed', role: 'coding' }));
    a.put(new Task({ id: 'keeper', role: 'coding' }));

    a.remove('doomed');
    // B never saw the removal; a stale merge would bring the deleted task
    // back into the index.
    b.put(new Task({ id: 'other', role: 'review' }));

    const index = JSON.parse(fs.readFileSync(path.join(dir, '_index.json'), 'utf-8'));
    assert.deepEqual(Object.keys(index.tasks).sort(), ['keeper', 'other']);
    assert.equal(a.get('doomed'), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
