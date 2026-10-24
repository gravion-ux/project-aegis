'use strict';

/**
 * Phase 2.1 — security hardening regression tests.
 *
 * Every test here corresponds to a defect that was *observed* before the
 * fix, not to a hypothetical. The audit that produced these findings is
 * written up in PHASE21_SECURITY_AUDIT.md; each finding names the test
 * that pins it.
 *
 * The tests are deterministic and offline: no network, no credentials, no
 * wall-clock dependence beyond explicit timeouts.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');

const { Storage } = require('../aegis/storage');
const { Memory } = require('../aegis/memory');
const { Checkpoint, CheckpointStore } = require('../aegis/recovery');
const { Budget, BudgetManager } = require('../aegis/usage');
const { Orchestrator, buildDefaultManifest } = require('../aegis/orchestrator');
const { buildDefaultRegistry } = require('../aegis/agent');
const { ToolRegistry, Tool, buildDefaultRegistry: buildTools } = require('../aegis/tools/registry');
const { HttpProvider } = require('../aegis/providers/http');
const { ProviderError } = require('../aegis/providers/base');
const { isSafeIdentifier } = require('../aegis/paths');
const { Task } = require('../aegis/task');

function tmpRoot(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `aegis-sec-${tag}-`));
}

function rm(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
}

// ===========================================================================
// FINDING 1 (HIGH) — path traversal through a task id
// Storage built a filename from a caller-supplied id with no validation, so
// `aegis tasks show ../../secret` read a file outside the state directory
// and a task with a traversing id wrote outside it.
// ===========================================================================

const TRAVERSAL_IDS = [
  '../escaped',
  '../../escaped',
  '..\\escaped',
  '/absolute/path',
  'C:\\windows\\path',
  'sub/../../escaped',
  './../escaped',
  '..',
  '.',
];

test('security: Storage.put refuses a traversing task id and writes nothing outside the root', () => {
  for (const id of TRAVERSAL_IDS) {
    const base = tmpRoot('sw');
    const root = path.join(base, 'state');
    fs.mkdirSync(root, { recursive: true });
    const s = new Storage(root);
    assert.throws(() => s.put(new Task({ id, title: 'x' })), (err) => err.code === 'INVALID_ID',
      `id ${JSON.stringify(id)} should be refused`);
    // nothing may have been created anywhere under base
    const created = fs.readdirSync(base).filter((f) => f !== 'state');
    assert.deepEqual(created, [], `id ${JSON.stringify(id)} created ${created.join(', ')}`);
    rm(base);
  }
});

test('security: Storage.get refuses a traversing task id', () => {
  const base = tmpRoot('sr');
  const root = path.join(base, 'state');
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(base, 'outside.json'), JSON.stringify({ id: 'secret', title: 'OUTSIDE' }));

  const s = new Storage(root);
  s._index.tasks['../outside'] = { id: '../outside', state: 'QUEUED' };
  assert.equal(s.get('../outside'), null);
  assert.equal(s.get('../../outside'), null);
  assert.equal(s.get('/etc/passwd'), null);
  rm(base);
});

test('security: Storage.remove refuses a traversing task id', () => {
  const base = tmpRoot('srm');
  const root = path.join(base, 'state');
  fs.mkdirSync(root, { recursive: true });
  const outside = path.join(base, 'outside.json');
  fs.writeFileSync(outside, 'keep me');

  const s = new Storage(root);
  s.remove('../outside');
  assert.ok(fs.existsSync(outside), 'remove() must not delete a file outside the state directory');
  rm(base);
});

test('security: valid task ids keep working', () => {
  const base = tmpRoot('ok');
  const s = new Storage(path.join(base, 'state'));
  const t = new Task({ title: 'valid' });
  s.put(t);
  assert.equal(s.get(t.id).title, 'valid');
  assert.equal(s.list().length, 1);
  s.remove(t.id);
  assert.equal(s.get(t.id), null);
  rm(base);
});

// ===========================================================================
// FINDING 2 (HIGH) — path traversal through a checkpoint task id
// ===========================================================================

test('security: CheckpointStore.save refuses a traversing task id', () => {
  for (const id of TRAVERSAL_IDS) {
    const base = tmpRoot('cp');
    const root = path.join(base, 'state');
    fs.mkdirSync(root, { recursive: true });
    const store = new CheckpointStore(root);
    assert.throws(() => store.save(new Checkpoint({ taskId: id })), (err) => err.code === 'INVALID_ID',
      `id ${JSON.stringify(id)} should be refused`);
    const created = fs.readdirSync(base).filter((f) => f !== 'state');
    assert.deepEqual(created, [], `id ${JSON.stringify(id)} created ${created.join(', ')}`);
    rm(base);
  }
});

test('security: CheckpointStore.load refuses a traversing task id', () => {
  const base = tmpRoot('cpl');
  const root = path.join(base, 'state');
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(base, 'outside.checkpoint.json'), JSON.stringify({ taskId: 'x', completed: [], pending: [], lastSeq: 0 }));
  const store = new CheckpointStore(root);
  assert.equal(store.load('../outside'), null);
  rm(base);
});

test('security: CheckpointStore.clear refuses a traversing task id', () => {
  const base = tmpRoot('cpc');
  const root = path.join(base, 'state');
  fs.mkdirSync(root, { recursive: true });
  const outside = path.join(base, 'outside.checkpoint.json');
  fs.writeFileSync(outside, 'keep me');
  const store = new CheckpointStore(root);
  store.clear('../outside');
  assert.ok(fs.existsSync(outside));
  rm(base);
});

test('security: a valid checkpoint still round-trips', () => {
  const base = tmpRoot('cpok');
  const store = new CheckpointStore(path.join(base, 'state'));
  const cp = new Checkpoint({ taskId: 't_ok', pending: [{ seq: 1, name: 's1', idempotencyKey: 't_ok#1' }] });
  store.save(cp);
  const loaded = store.load('t_ok');
  assert.equal(loaded.taskId, 't_ok');
  assert.equal(loaded.pending.length, 1);
  rm(base);
});

test('security: a corrupted checkpoint file is ignored, not thrown', () => {
  const base = tmpRoot('cpbad');
  const root = path.join(base, 'state');
  fs.mkdirSync(root, { recursive: true });
  const store = new CheckpointStore(root);
  fs.writeFileSync(path.join(root, 't_x.checkpoint.json'), '{ not json at all');
  assert.equal(store.load('t_x'), null);
  rm(base);
});

test('security: a checkpoint whose internal id does not match is not loaded', () => {
  const base = tmpRoot('cpid');
  const root = path.join(base, 'state');
  fs.mkdirSync(root, { recursive: true });
  const store = new CheckpointStore(root);
  fs.writeFileSync(path.join(root, 't_b.checkpoint.json'), JSON.stringify({
    taskId: 't_a', completed: [{ seq: 1, name: 'owned-by-a' }], pending: [], lastSeq: 1, version: 1,
  }));
  assert.equal(store.load('t_b'), null, 'a checkpoint for another task must not be adopted');
  rm(base);
});

// ===========================================================================
// FINDING 3 (HIGH) — path traversal through a memory project id
// The `memory` specialist passes task input straight through as projectId.
// ===========================================================================

test('security: Memory.add refuses a traversing project id', () => {
  for (const id of TRAVERSAL_IDS) {
    const base = tmpRoot('mem');
    const root = path.join(base, 'data');
    fs.mkdirSync(root, { recursive: true });
    const m = new Memory(root);
    assert.throws(() => m.add(id, { key: 'k', value: 'v' }), (err) => err.code === 'INVALID_ID',
      `project id ${JSON.stringify(id)} should be refused`);
    const created = fs.readdirSync(base).filter((f) => f !== 'data');
    assert.deepEqual(created, [], `project id ${JSON.stringify(id)} created ${created.join(', ')}`);
    rm(base);
  }
});

test('security: Memory checkpoint refuses a traversing project id', () => {
  const base = tmpRoot('memcp');
  const root = path.join(base, 'data');
  fs.mkdirSync(root, { recursive: true });
  const m = new Memory(root);
  assert.throws(() => m.saveCheckpoint('../escaped', { completed: [] }), (err) => err.code === 'INVALID_ID');
  const created = fs.readdirSync(base).filter((f) => f !== 'data');
  assert.deepEqual(created, []);
  rm(base);
});

test('security: valid project ids keep working', () => {
  const base = tmpRoot('memok');
  const m = new Memory(path.join(base, 'data'));
  const rec = m.add('p1', { key: 'stack', value: 'node' });
  assert.equal(rec.key, 'stack');
  assert.equal(m.list('p1').length, 1);
  assert.equal(m.list('default').length, 0);
  rm(base);
});

// ===========================================================================
// FINDING 4 (HIGH) — malformed identifiers
// ===========================================================================

test('security: malformed identifiers are rejected', () => {
  const bad = ['', '.', '..', 'a/b', 'a\\b', 'a\0b', 'C:evil', 'C:/evil', '//server/share',
    null, undefined, 42, {}, [], 'x'.repeat(300)];
  for (const id of bad) {
    assert.equal(isSafeIdentifier(id), false, `${JSON.stringify(id)} should not be a safe identifier`);
  }
});

test('security: ordinary identifiers are accepted', () => {
  const good = ['t_0123456789abcdef', 'p1', 'default', 'my-project', 'my_project', 'a.b.c', 'Task 1'];
  for (const id of good) {
    assert.equal(isSafeIdentifier(id), true, `${JSON.stringify(id)} should be a safe identifier`);
  }
});

// ===========================================================================
// FINDING 5 (MEDIUM) — a refused budget call still charged the budget
// `record()` incremented the counters and only then checked the limit, so
// a call that was refused still moved the budget.
// ===========================================================================

test('security: a refused Budget.record leaves the counters untouched', () => {
  const b = new Budget({ maxOutputChars: 10 });
  assert.throws(() => b.record({ output: 50 }), (err) => err.code === 'BUDGET_EXCEEDED');
  assert.equal(b.summary().outputChars, 0, 'a refused call must not charge the budget');
  assert.equal(b.summary().inputChars, 0);
  assert.equal(b.summary().exceeded, false);
  // and the budget is still usable afterwards
  b.record({ output: 5 });
  assert.equal(b.summary().outputChars, 5);
});

test('security: the budget error reports the unchanged totals', () => {
  const b = new Budget({ maxOutputChars: 10 });
  try { b.record({ output: 50 }); assert.fail('should have thrown'); }
  catch (err) {
    assert.equal(err.code, 'BUDGET_EXCEEDED');
    assert.equal(err.summary.outputChars, 0);
  }
});

test('security: non-finite usage is refused instead of disabling the limits', () => {
  const b = new Budget({ maxOutputChars: 10 });
  assert.throws(() => b.record({ output: NaN }), (err) => err.code === 'INVALID_USAGE');
  assert.throws(() => b.record({ output: Infinity }), (err) => err.code === 'INVALID_USAGE');
  assert.throws(() => b.record({ input: -5 }), (err) => err.code === 'INVALID_USAGE');
  assert.equal(b.summary().outputChars, 0);
  // the limit is still enforced after a rejected value
  assert.throws(() => b.record({ output: 50 }), (err) => err.code === 'BUDGET_EXCEEDED');
});

test('security: budget.guard() refuses once there is no headroom left', () => {
  const b = new Budget({ maxOutputChars: 10 });
  b.record({ output: 5 });
  assert.equal(b.guard(), false, 'there is still headroom');
  b.record({ output: 5 }); // exactly at the limit
  assert.throws(() => b.guard(), (err) => err.code === 'BUDGET_EXCEEDED');
});

test('security: a budget with no limits never blocks', () => {
  const b = new Budget({});
  b.record({ output: 100000 });
  assert.equal(b.guard(), false);
});

// ===========================================================================
// FINDING 6 (MEDIUM) — the BudgetManager preflight used the wrong keys
// `wouldExceed` takes {input, output, tokens} but was handed
// {inputChars, outputChars, tokens}, so the prospective check silently
// compared the *current* totals and never fired before the write.
// ===========================================================================

test('security: the global budget preflight fires before the usage is recorded', () => {
  const m = new BudgetManager();
  m.global.limits.inputChars = 50;
  m.record('t1', { input: 40, output: 0 });
  assert.equal(m.global.summary().inputChars, 40);
  // 40 + 40 = 80 > 50 — must be refused *before* either budget is mutated
  assert.throws(() => m.record('t1', { input: 40, output: 0 }), (err) => err.code === 'BUDGET_EXCEEDED');
  assert.equal(m.global.summary().inputChars, 40, 'a refused call must not charge the global budget');
  assert.equal(m.summary().perTask.find((t) => t.taskId === 't1').inputChars, 40,
    'a refused call must not charge the task budget');
});

test('security: per-task limits set after the first record are applied', () => {
  const m = new BudgetManager();
  m.record('t1', { input: 10, output: 0 });
  m.forTask('t1', { maxInputChars: 15 });
  assert.equal(m.byTask.get('t1').limits.inputChars, 15);
  assert.throws(() => m.record('t1', { input: 10, output: 0 }), (err) => err.code === 'BUDGET_EXCEEDED');
  assert.equal(m.byTask.get('t1').summary().inputChars, 10, 'a refused call must not charge the task budget');
});

test('security: a per-task limit is enforced independently of the global one', () => {
  const m = new BudgetManager();
  m.forTask('t1', { maxOutputChars: 10 });
  m.record('t1', { output: 8 });
  assert.throws(() => m.record('t1', { output: 8 }), (err) => err.code === 'BUDGET_EXCEEDED');
  // the global budget has no limit, so it must be untouched by the refusal
  assert.equal(m.global.summary().outputChars, 8);
});

// ===========================================================================
// FINDING 7 (MEDIUM) — the orchestrator had no budget gate
// The budget was recorded after the agent had already run, so an
// exhausted budget did not stop new work from starting.
// ===========================================================================

function orchestratorWith(role, agent, budget) {
  const agents = buildDefaultRegistry();
  const manifest = buildDefaultManifest(agents);
  manifest.declare({
    role, purpose: 'test', inputs: { type: 'object' }, allowedTools: [],
    outputSchema: { type: 'object' },
    resourceLimits: { maxIterations: 3, maxWallMs: 5000, maxDelegationDepth: 0 },
  });
  agents.register(agent);
  return new Orchestrator({
    manifest, agentRegistry: agents, toolRegistry: new ToolRegistry(), budget,
  });
}

test('security: the orchestrator refuses to start when the budget is exhausted', async () => {
  const budget = new Budget({});
  budget.record({ output: 100 });
  budget.limits.outputChars = 10; // the limit is tightened, so there is no headroom
  let ran = false;
  const o = orchestratorWith('budgetgate', {
    role: 'budgetgate',
    run: async () => { ran = true; return { status: 'SUCCEEDED', output: {}, evidence: [] }; },
  }, budget);
  await assert.rejects(() => o.run(new Task({ role: 'budgetgate' })), (err) => err.code === 'BUDGET_EXCEEDED');
  assert.equal(ran, false, 'the agent must not run when the budget is already exhausted');
});

test('security: every attempt is charged to the budget', async () => {
  const budget = new Budget({});
  const o = orchestratorWith('charged', {
    role: 'charged',
    run: async () => ({ status: 'SUCCEEDED', output: { a: 'b' }, evidence: [] }),
  }, budget);
  await o.run(new Task({ role: 'charged' }));
  assert.equal(budget.summary().attempts, 1);
  assert.ok(budget.summary().outputChars > 0);
});

test('security: a retry loop is charged for every attempt and can be bounded by the budget', async () => {
  const budget = new Budget({ maxAttempts: 2 });
  let attempts = 0;
  const o = orchestratorWith('retried', {
    role: 'retried',
    run: async () => { attempts += 1; throw new ProviderError('transient', { retryable: true }); },
  }, budget);
  await assert.rejects(() => o.run(new Task({ role: 'retried' })), (err) => err.code === 'BUDGET_EXCEEDED');
  assert.equal(attempts, 2, 'the budget must stop the retry loop');
  assert.equal(budget.summary().attempts, 2);
});

// ===========================================================================
// FINDING 8 (MEDIUM) — the tool registry ignored the abort signal
// ===========================================================================

test('security: a cancelled run does not start the tool', async () => {
  const reg = buildTools();
  let ran = false;
  reg.register(new Tool({
    name: 'probe', purpose: 'test', riskLevel: 'read',
    run: async () => { ran = true; return 'ok'; },
  }));
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    () => reg.run('probe', {}, { allowedTools: ['probe'], signal: controller.signal }),
    (err) => err.code === 'ABORTED',
  );
  assert.equal(ran, false, 'an aborted run must not execute the tool');
});

test('security: a timeout aborts the tool instead of abandoning it', async () => {
  const reg = buildTools();
  let observedAbort = false;
  reg.register(new Tool({
    name: 'slow', purpose: 'test', riskLevel: 'read', maxDurationMs: 60,
    run: async (input, ctx) => {
      await new Promise((resolve) => {
        const t = setTimeout(resolve, 2000);
        if (ctx.signal) {
          ctx.signal.addEventListener('abort', () => {
            observedAbort = true;
            clearTimeout(t);
            resolve();
          }, { once: true });
        }
      });
      return 'done';
    },
  }));
  await assert.rejects(
    () => reg.run('slow', {}, { allowedTools: ['slow'] }),
    (err) => err.code === 'TOOL_TIMEOUT',
  );
  // give the aborted tool a moment to unwind
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(observedAbort, true, 'the tool must be told to stop when it times out');
});

test('security: an external cancellation reaches a running tool', async () => {
  const reg = buildTools();
  let observedAbort = false;
  reg.register(new Tool({
    name: 'long', purpose: 'test', riskLevel: 'read', maxDurationMs: 5000,
    run: async (input, ctx) => {
      await new Promise((resolve) => {
        const t = setTimeout(resolve, 3000);
        if (ctx.signal) {
          ctx.signal.addEventListener('abort', () => {
            observedAbort = true;
            clearTimeout(t);
            resolve();
          }, { once: true });
        }
      });
      return 'done';
    },
  }));
  const controller = new AbortController();
  const p = reg.run('long', {}, { allowedTools: ['long'], signal: controller.signal });
  setTimeout(() => controller.abort(), 30);
  await p.catch(() => {});
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(observedAbort, true, 'cancelling the run must reach the tool');
});

// ===========================================================================
// FINDING 9 (MEDIUM) — denied tool calls had no guarantees about side effects
// ===========================================================================

test('security: a denied tool call never executes the tool body', async () => {
  const reg = buildTools();
  let ran = false;
  reg.register(new Tool({
    name: 'danger', purpose: 'test', riskLevel: 'destructive',
    run: async () => { ran = true; return 'ran'; },
  }));

  // not in allowedTools
  await assert.rejects(() => reg.run('danger', {}, { allowedTools: [] }), (err) => err.code === 'TOOL_DENIED');
  // over the risk ceiling
  await assert.rejects(
    () => reg.run('danger', {}, { allowedTools: ['danger'], maxRiskLevel: 'read' }),
    (err) => err.code === 'TOOL_DENIED',
  );
  // not registered at all
  await assert.rejects(() => reg.run('nope', {}, { allowedTools: ['nope'] }), (err) => err.code === 'TOOL_NOT_FOUND');

  assert.equal(ran, false, 'a denied call must not run the tool body');
});

test('security: a denial is audited', async () => {
  const reg = buildTools();
  const events = [];
  const audit = { append: (e) => events.push(e) };
  await assert.rejects(
    () => reg.run('http.get', { url: 'http://example.com/' }, { allowedTools: ['hash.sha256'], audit }),
    (err) => err.code === 'TOOL_DENIED',
  );
  assert.ok(events.some((e) => e.kind === 'tool.deny'));
});

// ===========================================================================
// FINDING 10 (MEDIUM) — fs.read had no size limit and followed symlinks
// ===========================================================================

test('security: fs.read refuses a file over the size limit', async () => {
  const base = tmpRoot('big');
  const root = path.join(base, 'allowed');
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'big.bin'), Buffer.alloc(2 * 1024 * 1024, 0x41));
  const reg = buildTools();
  await assert.rejects(
    () => reg.run('fs.read', { path: path.join(root, 'big.bin') }, { allowedTools: ['fs.read'], allowedRoots: [root] }),
    (err) => err.code === 'TOOL_OUTPUT_TOO_LARGE',
  );
  rm(base);
});

test('security: fs.read still reads a normal file inside an allowed root', async () => {
  const base = tmpRoot('read');
  const root = path.join(base, 'allowed');
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'ok.txt'), 'hello');
  const reg = buildTools();
  const out = await reg.run('fs.read', { path: path.join(root, 'ok.txt') }, { allowedTools: ['fs.read'], allowedRoots: [root] });
  assert.equal(out, 'hello');
  rm(base);
});

test('security: fs.read refuses a path outside the allowed roots', async () => {
  const base = tmpRoot('outside');
  const root = path.join(base, 'allowed');
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(base, 'secret.txt'), 'SECRET');
  const reg = buildTools();
  await assert.rejects(
    () => reg.run('fs.read', { path: path.join(base, 'secret.txt') }, { allowedTools: ['fs.read'], allowedRoots: [root] }),
    (err) => err.code === 'TOOL_DENIED',
  );
  rm(base);
});

test('security: fs.read refuses a traversal out of the allowed root', async () => {
  const base = tmpRoot('trav');
  const root = path.join(base, 'allowed');
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(base, 'secret.txt'), 'SECRET');
  const reg = buildTools();
  await assert.rejects(
    () => reg.run('fs.read', { path: path.join(root, '..', 'secret.txt') }, { allowedTools: ['fs.read'], allowedRoots: [root] }),
    (err) => err.code === 'TOOL_DENIED',
  );
  rm(base);
});

test('security: fs.read refuses to follow a symlink out of the allowed root', (t) => {
  const base = tmpRoot('symlink');
  const root = path.join(base, 'allowed');
  fs.mkdirSync(root, { recursive: true });
  const secret = path.join(base, 'secret.txt');
  fs.writeFileSync(secret, 'SECRET');
  try {
    fs.symlinkSync(secret, path.join(root, 'link.txt'));
  } catch (err) {
    // Creating a symlink needs a privilege this Windows account lacks.
    // The assertion still runs on the Linux CI runner.
    t.skip(`symlink creation is not permitted here (${err.code || err.message}); covered by CI`);
    rm(base);
    return;
  }
  const reg = buildTools();
  return assert.rejects(
    () => reg.run('fs.read', { path: path.join(root, 'link.txt') }, { allowedTools: ['fs.read'], allowedRoots: [root] }),
    (err) => err.code === 'TOOL_DENIED',
  ).finally(() => rm(base));
});

// ===========================================================================
// FINDING 11 (MEDIUM) — http.get buffered an unbounded response
// ===========================================================================

test('security: http.get refuses a response over the size limit', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    res.end(Buffer.alloc(2 * 1024 * 1024, 0x42));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  const reg = buildTools();
  try {
    await assert.rejects(
      () => reg.run('http.get', { url }, { allowedTools: ['http.get'] }),
      (err) => err.code === 'TOOL_OUTPUT_TOO_LARGE',
    );
  } finally {
    server.close();
  }
});

test('security: http.get still fetches a loopback URL', async () => {
  const server = http.createServer((req, res) => { res.writeHead(200); res.end('ok-body'); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  const reg = buildTools();
  try {
    const out = await reg.run('http.get', { url }, { allowedTools: ['http.get'] });
    assert.equal(out.status, 200);
    assert.equal(out.body, 'ok-body');
  } finally {
    server.close();
  }
});

test('security: http.get refuses a non-loopback host', async () => {
  const reg = buildTools();
  await assert.rejects(
    () => reg.run('http.get', { url: 'http://example.com/' }, { allowedTools: ['http.get'] }),
    (err) => err.code === 'TOOL_DENIED',
  );
});

// ===========================================================================
// FINDING 12 (MEDIUM) — the CLI died with a fatal error on a missing task
// `Task.fromJSON(null)` throws, and the router called it before checking
// the result, so "no such task" became a crash.
// ===========================================================================

test('security: the CLI reports a missing task as a usage error, not a crash', () => {
  const base = tmpRoot('cli');
  const cli = path.join(ROOT, 'aegis', 'cli.js');
  for (const cmd of [['tasks', 'run'], ['tasks', 'cancel'], ['tasks', 'show']]) {
    const r = spawnSync(process.execPath, [cli, ...cmd, 't_missing', '--root', base], {
      encoding: 'utf-8', timeout: 15_000,
    });
    assert.equal(r.status, 2, `${cmd.join(' ')} should exit 2, stderr: ${r.stderr}`);
    assert.ok(!/fatal:/.test(r.stderr), `${cmd.join(' ')} should not be a fatal error`);
    const out = JSON.parse(r.stdout);
    assert.match(out.error, /no such task/);
  }
  rm(base);
});

// ===========================================================================
// FINDING 13 (LOW) — the HTTP provider buffered an unbounded response and
// could echo a secret into an error message
// ===========================================================================

test('security: the HTTP provider refuses an oversized response', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(Buffer.alloc(2 * 1024 * 1024, 0x43));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  const p = new HttpProvider({ baseUrl: url, model: 'm', maxResponseBytes: 1024 });
  try {
    await assert.rejects(
      () => p.complete({ messages: [{ role: 'user', content: 'ping' }] }),
      (err) => err instanceof ProviderError && /exceeded/.test(err.message),
    );
  } finally {
    server.close();
  }
});

test('security: an error body that echoes a token is redacted', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(500, { 'content-type': 'text/plain' });
    // a server that echoes what it was sent
    res.end('token=sk-super-secret-value');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  const p = new HttpProvider({ baseUrl: url, model: 'm' });
  try {
    await assert.rejects(
      () => p.complete({ messages: [{ role: 'user', content: 'ping' }] }),
      (err) => {
        assert.ok(err instanceof ProviderError);
        assert.ok(!err.message.includes('sk-super-secret-value'), 'the secret must not reach the error message');
        assert.match(err.message, /REDACTED/);
        return true;
      },
    );
  } finally {
    server.close();
  }
});

test('security: the provider auth header is sent but never echoed back', async () => {
  let seenAuth = null;
  const server = http.createServer((req, res) => {
    seenAuth = req.headers.authorization || null;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ text: 'ok' }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  const p = new HttpProvider({ baseUrl: url, model: 'm', authHeader: 'Bearer test-token-abc123' });
  try {
    const out = await p.complete({ messages: [{ role: 'user', content: 'ping' }] });
    assert.equal(seenAuth, 'Bearer test-token-abc123', 'the header must be sent');
    assert.ok(!JSON.stringify(out).includes('test-token-abc123'), 'the header must not be echoed in the result');
  } finally {
    server.close();
  }
});

test('security: the configured budget limits are applied, not just displayed', () => {
  const base = tmpRoot('cfgbudget');
  const { createContext } = require('../aegis/index');
  const ctx = createContext({ root: base, env: {} });
  // The config declares maxOutputChars: 200000. The manager must carry
  // that limit, otherwise `aegis usage` displays a limit that nothing
  // enforces.
  assert.equal(ctx.config.budget.maxOutputChars, 200000);
  assert.equal(ctx.budgets.global.limits.outputChars, 200000,
    'the configured limit must be applied to the budget that enforces it');
  assert.equal(ctx.budgets.global.limits.outputChars, ctx.config.budget.maxOutputChars);
  rm(base);
});

test('security: the configured budget is enforced by the orchestrator', async () => {
  const base = tmpRoot('cfgorch');
  const { createContext } = require('../aegis/index');
  const ctx = createContext({ root: base, env: {} });
  // record within the configured limit, then tighten it so there is no
  // headroom left for another attempt
  ctx.budgets.global.record({ output: 50 });
  ctx.budgets.global.limits.outputChars = 10;

  let ran = false;
  const agents = buildDefaultRegistry();
  const manifest = buildDefaultManifest(agents);
  manifest.declare({
    role: 'cfggate', purpose: 'test', inputs: { type: 'object' }, allowedTools: [],
    outputSchema: { type: 'object' },
    resourceLimits: { maxIterations: 2, maxWallMs: 5000, maxDelegationDepth: 0 },
  });
  agents.register({
    role: 'cfggate',
    run: async () => { ran = true; return { status: 'SUCCEEDED', output: {}, evidence: [] }; },
  });
  const o = new Orchestrator({
    manifest, agentRegistry: agents, toolRegistry: new ToolRegistry(), budget: ctx.budgets,
  });
  await assert.rejects(() => o.run(new Task({ role: 'cfggate' })), (err) => err.code === 'BUDGET_EXCEEDED');
  assert.equal(ran, false, 'the configured budget must stop the run');
  rm(base);
});

// ===========================================================================
// FINDING 14 — recovery stays idempotent and cancellation stays cooperative
// ===========================================================================

test('security: repeated recovery does not execute a step twice', () => {
  const base = tmpRoot('idem');
  const store = new CheckpointStore(path.join(base, 'state'));
  const cp = new Checkpoint({
    taskId: 't_1',
    pending: [
      { seq: 1, name: 'step-1', idempotencyKey: 't_1#1' },
      { seq: 2, name: 'step-2', idempotencyKey: 't_1#2' },
    ],
  });
  const executed = [];
  const runStep = (s) => {
    const next = cp.nextPending();
    if (!next) return;
    executed.push(next.seq);
    cp.markCompleted({ seq: next.seq, name: next.name, idempotencyKey: next.idempotencyKey });
    store.save(cp);
  };
  runStep(); runStep();
  store.save(cp);
  // a second process would resume from the checkpoint
  const reloaded = store.load('t_1');
  const next = reloaded.nextPending();
  assert.equal(next, null, 'both steps are already complete');
  assert.deepEqual(executed, [1, 2]);
  rm(base);
});

test('security: the orchestrator stops when the run is cancelled between iterations', async () => {
  const controller = new AbortController();
  let runs = 0;
  const agents = buildDefaultRegistry();
  const manifest = buildDefaultManifest(agents);
  manifest.declare({
    role: 'cancellable', purpose: 'test', inputs: { type: 'object' }, allowedTools: [],
    outputSchema: { type: 'object' },
    resourceLimits: { maxIterations: 5, maxWallMs: 5000, maxDelegationDepth: 0 },
  });
  agents.register({
    role: 'cancellable',
    run: async () => {
      runs += 1;
      controller.abort(); // cancel after the first attempt
      throw new ProviderError('transient', { retryable: true });
    },
  });
  const o = new Orchestrator({
    manifest, agentRegistry: agents, toolRegistry: new ToolRegistry(), budget: null,
  });
  await assert.rejects(
    () => o.run(new Task({ role: 'cancellable' }), { signal: controller.signal }),
    (err) => err.code === 'ABORTED',
  );
  assert.equal(runs, 1, 'a cancelled run must not start another iteration');
});
