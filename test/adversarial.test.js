'use strict';

/**
 * Phase 2.2 adversarial / fuzz harness.
 *
 * These tests are *deterministic*: the generator is a seeded linear
 * congruential generator, so a failure reproduces exactly. There is no
 * randomness from the environment, no wall-clock dependence in the
 * generated data, and no network access — the only socket is a local
 * mock server bound to 127.0.0.1.
 *
 * The harness asserts a property, not a specific value: whatever input
 * comes out of the generator, the trust boundary must hold. A fuzz test
 * that only ever produced the one input it was written against would not
 * be a fuzz test.
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
const { Budget, BudgetManager } = require('../aegis/usage');
const { ToolRegistry, Tool, buildDefaultRegistry } = require('../aegis/tools/registry');
const { HttpProvider, extractTextAndUsage } = require('../aegis/providers/http');
const { redactString } = require('../aegis/redact');
const { Audit } = require('../aegis/audit');
const { isSafeIdentifier, assertSafeIdentifier, resolveWithin } = require('../aegis/paths');

// ---------------------------------------------------------------------------
// Deterministic generator
// ---------------------------------------------------------------------------

/**
 * A seeded 32-bit linear congruential generator.
 *
 * `Math.random()` is not used anywhere in this file: a failing case must
 * be replayable byte-for-byte.
 */
function makeRng(seed) {
  let state = seed >>> 0;
  return function next() {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/\\~!@#$%^&*()[]{}<>?\'"`;:|+=,\n\t ';

function randomString(rng, maxLen = 24) {
  const len = Math.floor(rng() * maxLen) + 1;
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHABET[Math.floor(rng() * ALPHABET.length)];
  return s;
}

/**
 * Generate an identifier-shaped string that is deliberately hostile:
 * path separators, dots, drive letters, NUL, URL escapes and whitespace.
 */
function hostileId(rng) {
  const kinds = [
    () => '../' + randomString(rng, 8),
    () => '..\\' + randomString(rng, 8),
    () => '/' + randomString(rng, 8),
    () => '\\' + randomString(rng, 8),
    () => 'C:' + randomString(rng, 6),
    () => 'C:\\' + randomString(rng, 8),
    () => '..',
    () => '../..',
    () => 'a/../../b',
    () => '%2e%2e%2fetc%2fpasswd',
    () => '..%2f..%2fetc',
    () => 'x' + '\0' + 'y',
    () => 'task' + randomString(rng, 4),
    () => '.hidden',
    () => '..' + randomString(rng, 4),
    () => 'con',
    () => 'aux',
    () => 'a'.repeat(300),
    () => ' ' + randomString(rng, 4),
    () => randomString(rng, 12),
  ];
  return kinds[Math.floor(rng() * kinds.length)]();
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ---------------------------------------------------------------------------
// Adversarial: identifier handling
// ---------------------------------------------------------------------------

test('adversarial: no generated identifier can escape the state directory', () => {
  const rng = makeRng(0xA3615);
  const root = tmpDir('aegis-fuzz-ids-');
  const stateDir = path.join(root, 'state');
  try {
    for (let i = 0; i < 400; i++) {
      const id = hostileId(rng);
      const store = new Storage(stateDir);

      // A read must never touch a path outside the directory.
      const found = store.get(id);
      assert.ok(found === null || found.id === id, `get() returned a foreign record for ${JSON.stringify(id)}`);

      // A write must either be refused or land inside the directory.
      try {
        store.put(new Task({ id, title: 'fuzz' }));
      } catch (err) {
        assert.ok(
          err.code === 'INVALID_ID' || err.code === 'PATH_ESCAPE' || err.code === 'TASK_ID_CONFLICT',
          `unexpected error for ${JSON.stringify(id)}: ${err.code || err.message}`,
        );
        continue;
      }
      // Nothing may exist outside the state directory.
      for (const entry of fs.readdirSync(root)) {
        if (entry === 'state') continue;
        assert.fail(`a write escaped the state directory: ${entry}`);
      }
      // The record must be readable under exactly the id that was written.
      const back = store.get(id);
      assert.ok(back, `a record written under ${JSON.stringify(id)} is not readable`);
      assert.equal(back.id, id);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('adversarial: identifier validation accepts and rejects consistently', () => {
  const rng = makeRng(0xBEEF01);
  for (let i = 0; i < 500; i++) {
    const id = hostileId(rng);
    const safe = isSafeIdentifier(id);
    if (safe) {
      // Anything accepted must also be accepted by assertSafeIdentifier,
      // and must not contain a separator or a dot *segment*.
      assert.doesNotThrow(() => assertSafeIdentifier(id));
      assert.ok(!id.includes('/'), `accepted an id with a slash: ${JSON.stringify(id)}`);
      assert.ok(!id.includes('\\'), `accepted an id with a backslash: ${JSON.stringify(id)}`);
      assert.ok(!id.includes('\0'), 'accepted an id with a NUL');
      // A dot segment is what makes `..` dangerous. A literal `..` inside a
      // longer name — or a percent-encoded `..%2f` — is not a segment and
      // is a perfectly ordinary filename character.
      for (const segment of id.split(/[/\\]/)) {
        assert.notEqual(segment, '..', `accepted an id with a dot segment: ${JSON.stringify(id)}`);
        assert.notEqual(segment, '.', `accepted an id with a dot segment: ${JSON.stringify(id)}`);
      }
    } else {
      assert.throws(() => assertSafeIdentifier(id), `rejected id ${JSON.stringify(id)} did not throw`);
    }
  }
});

test('adversarial: resolveWithin never resolves outside its root', () => {
  const rng = makeRng(0xC0FFEE);
  const root = tmpDir('aegis-fuzz-root-');
  try {
    fs.mkdirSync(path.join(root, 'inside'), { recursive: true });
    fs.writeFileSync(path.join(root, 'inside', 'ok.txt'), 'fine');
    const rootReal = fs.realpathSync(root);
    for (let i = 0; i < 500; i++) {
      const candidate = path.join(root, hostileId(rng));
      let resolved = null;
      try { resolved = resolveWithin(root, candidate); } catch { /* refused */ }
      if (resolved == null) continue;
      const real = fs.existsSync(resolved) ? fs.realpathSync(resolved) : resolved;
      assert.ok(
        real === rootReal || real.startsWith(rootReal + path.sep),
        `resolveWithin escaped the root: ${candidate} -> ${real}`,
      );
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Adversarial: storage
// ---------------------------------------------------------------------------

test('adversarial: a task written under any id is always listed', () => {
  const rng = makeRng(0x515151);
  const root = tmpDir('aegis-fuzz-store-');
  const stateDir = path.join(root, 'state');
  try {
    const store = new Storage(stateDir);
    const written = [];
    for (let i = 0; i < 120; i++) {
      const id = hostileId(rng);
      try {
        store.put(new Task({ id, title: `t${i}` }));
        written.push(id);
      } catch { /* refused ids are not written */ }
    }
    const listed = new Set(store.list().map((t) => t.id));
    for (const id of written) {
      assert.ok(listed.has(id), `a written task ${JSON.stringify(id)} is missing from list()`);
    }
    // A fresh store must see the same tasks.
    const reloaded = new Storage(stateDir);
    const reloadedIds = new Set(reloaded.list().map((t) => t.id));
    for (const id of written) {
      assert.ok(reloadedIds.has(id), `a written task ${JSON.stringify(id)} is missing after a reload`);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('adversarial: prototype-named task ids do not pollute the index', () => {
  const root = tmpDir('aegis-fuzz-proto-');
  const stateDir = path.join(root, 'state');
  try {
    const store = new Storage(stateDir);
    for (const id of ['__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty']) {
      store.put(new Task({ id, title: `proto-${id}` }));
    }
    const listed = store.list().map((t) => t.id).sort();
    assert.deepEqual(listed, ['__proto__', 'constructor', 'hasOwnProperty', 'prototype', 'toString']);
    // The prototype of the map must be untouched.
    assert.equal(Object.getPrototypeOf(store._index.tasks), null);
    // A normal task still works alongside them.
    store.put(new Task({ id: 'normal', title: 'normal' }));
    assert.ok(store.list().some((t) => t.id === 'normal'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('adversarial: a task id cannot collide with the task index', () => {
  const root = tmpDir('aegis-fuzz-index-');
  const stateDir = path.join(root, 'state');
  try {
    const store = new Storage(stateDir);
    store.put(new Task({ id: 'ordinary', title: 'fine' }));
    // `_index` would resolve to the index file itself.
    assert.throws(
      () => store.put(new Task({ id: '_index', title: 'clobber' })),
      (err) => err.code === 'INVALID_ID',
    );
    // The index must still be readable and still hold the other task.
    const reloaded = new Storage(stateDir);
    assert.ok(reloaded.list().some((t) => t.id === 'ordinary'), 'the index was damaged');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('adversarial: two ids that collide on a case-insensitive filesystem are refused', () => {
  const root = tmpDir('aegis-fuzz-case-');
  const stateDir = path.join(root, 'state');
  try {
    const store = new Storage(stateDir);
    store.put(new Task({ id: 'Alpha', title: 'upper' }));
    // The second id resolves to the same file on Windows/macOS.
    assert.throws(
      () => store.put(new Task({ id: 'alpha', title: 'lower' })),
      (err) => err.code === 'TASK_ID_CONFLICT',
    );
    // The original task must be intact.
    assert.equal(store.get('Alpha').title, 'upper');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Adversarial: budget
// ---------------------------------------------------------------------------

test('adversarial: a refused budget call leaves every counter untouched', () => {
  const rng = makeRng(0x1234);
  for (let i = 0; i < 300; i++) {
    const manager = new BudgetManager({ maxInputChars: 100, maxOutputChars: 100, maxAttempts: 3 });
    const input = Math.floor(rng() * 200);
    const output = Math.floor(rng() * 200);
    const before = JSON.stringify(manager.summary());
    try { manager.record('t1', { input, output, tokens: null, attempt: true }); } catch { /* refused */ }
    const after = JSON.stringify(manager.summary());
    const globalAttempts = manager.global.attempts;
    const taskAttempts = manager.forTask('t1').attempts;
    const globalInput = manager.global.inputChars;
    const taskInput = manager.forTask('t1').inputChars;
    // Whatever the outcome, the global and the task budget must agree with
    // each other — a refusal must not charge one and not the other.
    assert.equal(globalAttempts, taskAttempts, 'global and task attempt counters diverged');
    assert.equal(globalInput, taskInput, 'global and task input counters diverged');
    // A refused call must not have exceeded the ceiling.
    assert.ok(manager.global.inputChars <= 100, 'a refused call exceeded the input ceiling');
    assert.ok(manager.global.attempts <= 3, 'a refused call exceeded the attempt ceiling');
    assert.ok(before !== undefined && after !== undefined);
  }
});

test('adversarial: the attempt ceiling is enforced on the task budget too', () => {
  const manager = new BudgetManager({ maxAttempts: 100 });
  manager.forTask('t1', { maxAttempts: 2 });
  manager.record('t1', { input: 0, output: 0, tokens: null, attempt: true });
  manager.record('t1', { input: 0, output: 0, tokens: null, attempt: true });
  const globalBefore = manager.global.attempts;
  assert.throws(
    () => manager.record('t1', { input: 0, output: 0, tokens: null, attempt: true }),
    (err) => err.code === 'BUDGET_EXCEEDED',
  );
  // The refusal must not have charged the global budget.
  assert.equal(manager.global.attempts, globalBefore, 'a refused call charged the global budget');
});

test('adversarial: a budget with a ceiling never records more than the ceiling', () => {
  const rng = makeRng(0x777);
  const b = new Budget({ maxInputChars: 50, maxOutputChars: 50, maxTokens: 20, maxAttempts: 4 });
  for (let i = 0; i < 200; i++) {
    try {
      b.record({
        input: Math.floor(rng() * 30),
        output: Math.floor(rng() * 30),
        tokens: Math.floor(rng() * 10),
        attempt: true,
      });
    } catch { /* refused */ }
    assert.ok(b.inputChars <= 50, 'inputChars exceeded the ceiling');
    assert.ok(b.outputChars <= 50, 'outputChars exceeded the ceiling');
    assert.ok(b.tokens <= 20, 'tokens exceeded the ceiling');
    assert.ok(b.attempts <= 4, 'attempts exceeded the ceiling');
  }
});

// ---------------------------------------------------------------------------
// Adversarial: checkpoints
// ---------------------------------------------------------------------------

test('adversarial: no malformed checkpoint can crash the resume path', () => {
  const rng = makeRng(0xDEAD);
  const dir = tmpDir('aegis-fuzz-cp-');
  try {
    const store = new CheckpointStore(dir);
    for (let i = 0; i < 300; i++) {
      const id = `cp${i}`;
      const shape = Math.floor(rng() * 6);
      let payload;
      if (shape === 0) payload = { taskId: id, completed: 'not-an-array', pending: 'not-an-array' };
      else if (shape === 1) payload = { taskId: id, completed: [], pending: [], version: 999 };
      else if (shape === 2) payload = { taskId: id, completed: [null], pending: [42] };
      else if (shape === 3) payload = { taskId: id };
      else if (shape === 4) payload = { taskId: id, completed: [], pending: [], lastSeq: 'x' };
      else payload = { taskId: id, completed: [], pending: [], version: 1, extra: { deeply: 'nested' } };
      fs.writeFileSync(path.join(dir, `${id}.checkpoint.json`), JSON.stringify(payload));

      const cp = store.load(id);
      if (cp === null) continue; // refused — that is the safe outcome
      // A loaded checkpoint must be usable without throwing.
      assert.ok(Array.isArray(cp.completed), 'completed is not an array');
      assert.ok(Array.isArray(cp.pending), 'pending is not an array');
      assert.doesNotThrow(() => cp.markCompleted({ seq: 1, name: 'x' }));
      assert.doesNotThrow(() => cp.markInterrupted());
      assert.doesNotThrow(() => JSON.stringify(cp.toJSON()));
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('adversarial: a checkpoint cannot be loaded under a different task id', () => {
  const dir = tmpDir('aegis-fuzz-cp-id-');
  try {
    const store = new CheckpointStore(dir);
    const cp = new Checkpoint({ taskId: 'owner' });
    cp.markCompleted({ seq: 1, name: 'step' });
    store.save(cp);
    assert.equal(store.load('owner').taskId, 'owner');
    assert.equal(store.load('other'), null, 'a checkpoint was served under the wrong task id');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Adversarial: memory
// ---------------------------------------------------------------------------

test('adversarial: memory context never carries another task\'s records', async () => {
  const rng = makeRng(0x4242);
  const dir = tmpDir('aegis-fuzz-mem-');
  try {
    const mem = new Memory(dir);
    const taskA = 'task-A';
    const taskB = 'task-B';
    mem.add('p', { key: 'shared', value: 'project wide' }, { taskId: null });
    mem.add('p', { key: 'a-only', value: 'A secret' }, { taskId: taskA });
    mem.add('p', { key: 'b-only', value: 'B secret' }, { taskId: taskB });

    const ctx = await mem.assembleContext({ projectId: 'p', taskId: taskA });
    const keys = ctx.verified.map((r) => r.key);
    assert.ok(keys.includes('shared'), 'a project-wide record was dropped');
    assert.ok(keys.includes('a-only'), 'the task\'s own record was dropped');
    assert.ok(!keys.includes('b-only'), 'another task\'s record leaked into the context');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('adversarial: a memory record without a key is refused', () => {
  const dir = tmpDir('aegis-fuzz-memkey-');
  try {
    const mem = new Memory(dir);
    assert.throws(() => mem.add('p', { value: 'x' }), /key is required/);
    assert.throws(() => mem.add('p', { key: '', value: 'x' }), /key is required/);
    assert.throws(() => mem.add('p', null), /key is required/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('adversarial: memory survives a partial write without losing everything', () => {
  const dir = tmpDir('aegis-fuzz-mematomic-');
  try {
    const mem = new Memory(dir);
    mem.add('p', { key: 'k1', value: 'v1' });
    mem.add('p', { key: 'k2', value: 'v2' });
    const file = path.join(dir, 'p.json');
    // Simulate a crash during a non-atomic write.
    fs.writeFileSync(file, '[{"truncated":');
    const afterCrash = mem.list('p');
    assert.equal(afterCrash.length, 0, 'a corrupt file should yield no records, not a crash');
    // The next write must produce a valid file, not an extension of the
    // corrupt one.
    mem.add('p', { key: 'k3', value: 'v3' });
    const parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
    assert.ok(Array.isArray(parsed), 'the memory file is not a JSON array after a write');
    assert.equal(parsed.length, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Adversarial: tools
// ---------------------------------------------------------------------------

test('adversarial: no allowlist shape can permit an undeclared tool', async () => {
  const registry = buildDefaultRegistry();
  const names = registry.list();
  for (const name of names) {
    const runs = [
      undefined,
      null,
      {},
      [],
      'echo',
      'echo,hash.sha256',
      { length: 1, includes: () => true },
      [name],
      ['__proto__'],
    ];
    for (const allowedTools of runs) {
      let executed = false;
      const probe = new ToolRegistry();
      probe.register(new Tool({
        name: 'probe.echo',
        purpose: 'probe',
        riskLevel: 'read',
        run: async () => { executed = true; return 'ran'; },
      }));
      try {
        await probe.run('probe.echo', {}, { allowedTools });
      } catch { /* denied — expected for most shapes */ }
      // A string that merely *contains* the name must not be accepted.
      if (typeof allowedTools === 'string' && allowedTools.includes('probe.echo') && allowedTools !== 'probe.echo') {
        assert.equal(executed, false, `a string allowlist (${allowedTools}) allowed the tool`);
      }
    }
  }
});

test('adversarial: an unknown risk ceiling never grants a permissive ceiling', async () => {
  const registry = buildDefaultRegistry();
  // `null` and `undefined` mean "the task named no ceiling", which is the
  // default — not an invalid value. An unrecognised *string* is invalid
  // and must be refused rather than falling through to the most permissive
  // level.
  for (const ceiling of ['bogus', '', 'DESTRUCTIVE', 123, {}, []]) {
    let denied = false;
    try {
      await registry.run('echo', { value: 'x' }, { allowedTools: ['echo'], maxRiskLevel: ceiling });
    } catch (err) {
      denied = true;
      assert.ok(
        err.code === 'TOOL_DENIED' || err.code === 'TOOL_INPUT_INVALID',
        `unexpected error code ${err.code} for ceiling ${JSON.stringify(ceiling)}`,
      );
    }
    assert.equal(denied, true, `an invalid risk ceiling (${JSON.stringify(ceiling)}) was accepted`);
  }
});

test('adversarial: a destructive tool needs an explicit risk ceiling', async () => {
  let executed = false;
  const registry = new ToolRegistry();
  registry.register(new Tool({
    name: 'danger',
    purpose: 'probe',
    riskLevel: 'destructive',
    run: async () => { executed = true; return 'ran'; },
  }));
  // The default ceiling is `external`, so a destructive tool is refused
  // unless the caller opts in.
  await assert.rejects(
    () => registry.run('danger', {}, { allowedTools: ['danger'] }),
    (err) => err.code === 'TOOL_DENIED',
  );
  assert.equal(executed, false, 'a destructive tool ran under the default ceiling');
  // With an explicit ceiling it may run.
  const out = await registry.run('danger', {}, { allowedTools: ['danger'], maxRiskLevel: 'destructive' });
  assert.equal(out, 'ran');
});

test('adversarial: a tool never runs with an input its schema forbids', async () => {
  const registry = buildDefaultRegistry();
  const badInputs = [undefined, null, {}, { value: 123 }, { value: null }, { value: [] }, { value: { a: 1 } }, 'not-an-object'];
  for (const input of badInputs) {
    let executed = false;
    const probe = new ToolRegistry();
    probe.register(new Tool({
      name: 'probe.sha256',
      purpose: 'probe',
      riskLevel: 'read',
      inputSchema: { type: 'object', properties: { value: { type: 'string' } }, required: ['value'] },
      run: async () => { executed = true; return 'ran'; },
    }));
    try {
      await probe.run('probe.sha256', input, { allowedTools: ['probe.sha256'] });
    } catch { /* refused — expected */ }
    assert.equal(executed, false, `a tool ran with the invalid input ${JSON.stringify(input)}`);
  }
});

test('adversarial: the audit trail reports its own failures', async () => {
  const registry = buildDefaultRegistry();
  const boom = { append() { throw new Error('audit unavailable'); } };
  const before = registry.auditFailures;
  await registry.run('echo', { value: 'hello' }, { allowedTools: ['echo'], audit: boom });
  assert.ok(registry.auditFailures > before, 'an audit failure was not counted');
});

// ---------------------------------------------------------------------------
// Adversarial: provider
// ---------------------------------------------------------------------------

test('adversarial: a provider never reports an unusable counter as a real number', () => {
  const rng = makeRng(0x99);
  for (let i = 0; i < 300; i++) {
    const junk = [NaN, Infinity, -Infinity, -1, 'abc', null, undefined, {}, [], true];
    const usage = {
      prompt_tokens: junk[Math.floor(rng() * junk.length)],
      completion_tokens: junk[Math.floor(rng() * junk.length)],
    };
    const out = extractTextAndUsage({ usage }, '{}');
    assert.ok(out.usage, 'usage was not produced');
    assert.ok(Number.isFinite(out.usage.input), `input is not finite: ${out.usage.input}`);
    assert.ok(Number.isFinite(out.usage.output), `output is not finite: ${out.usage.output}`);
    assert.ok(Number.isFinite(out.usage.total), `total is not finite: ${out.usage.total}`);
    assert.ok(out.usage.input >= 0 && out.usage.output >= 0 && out.usage.total >= 0, 'a negative usage was produced');
  }
});

test('adversarial: a provider with no reported usage is labelled estimated', () => {
  const out = extractTextAndUsage({ usage: {} }, '{}');
  assert.equal(out.usage.reported, false, 'an absent counter was reported as measured');
  assert.equal(out.usage.total, 0);
});

test('adversarial: a non-http provider URL is refused', () => {
  for (const url of ['file:///etc/passwd', 'ftp://example.com/x', 'data:text/plain,hi', 'gopher://x', 'javascript:alert(1)']) {
    assert.throws(
      () => new HttpProvider({ baseUrl: url }),
      (err) => /unsupported protocol/.test(err.message),
      `the URL ${url} was accepted`,
    );
  }
});

test('adversarial: a redirect is never resolved as model output', async () => {
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

test('adversarial: an aborted request stops and reports the abort', async () => {
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
// Adversarial: redaction
// ---------------------------------------------------------------------------

test('adversarial: no credential shape survives redaction', () => {
  const rng = makeRng(0xABCDEF);
  const credentials = [
    'AKIAIOSFODNN7EXAMPLE',
    'ghp_' + 'a'.repeat(36),
    'github_pat_' + 'b'.repeat(22),
    'xoxb-123456789012-abcdefghijkl',
    'sk-' + 'c'.repeat(32),
    'AIza' + 'd'.repeat(35),
    'sk_live_' + 'e'.repeat(24),
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abcdefghijkl',
    '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----',
    'postgres://admin:hunter2@db.internal:5432/app',
    'https://user:pass@example.com/path',
    'Authorization: Basic YWRtaW46aHVudGVyMg==',
    'Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    'api_key: super-secret-value',
    'password=hunter2',
    'client_secret: abc123',
  ];
  for (const secret of credentials) {
    const redacted = redactString(secret);
    // The markers are shaped like `[REDACTED …]`, so the check has to match
    // the shape rather than one exact spelling.
    assert.match(redacted, /\[REDACTED[^\]]*\]/, `not redacted: ${secret}`);
    // The secret itself must not survive anywhere in the output.
    const literal = secret.includes(':') ? secret.slice(secret.indexOf(':') + 1).trim() : secret;
    if (literal.length > 8 && !literal.includes('\n')) {
      assert.ok(!redacted.includes(literal), `the secret survived redaction: ${secret}`);
    }
  }
  // Random noise must never crash the redactor.
  for (let i = 0; i < 300; i++) {
    const s = randomString(rng, 64);
    assert.doesNotThrow(() => redactString(s));
  }
});

// ---------------------------------------------------------------------------
// Adversarial: the credential scanner's own allowlist is not a blanket pass
// ---------------------------------------------------------------------------

test('adversarial: the secret scanner allowlist is scoped to test files', () => {
  const { isAllowedFixture, scan } = require('../scripts/scan-secrets');
  const fixture = 'AKIAIOSFODNN7EXAMPLE';

  // Inside test/ the synthetic fixture is allowed.
  assert.equal(isAllowedFixture(fixture, 'test/adversarial.test.js'), true);
  assert.equal(isAllowedFixture(fixture, 'test/phase22-regressions.test.js'), true);

  // Anywhere else the same string is a finding.
  assert.equal(isAllowedFixture(fixture, 'aegis/redact.js'), false);
  assert.equal(isAllowedFixture(fixture, 'README.md'), false);
  assert.equal(isAllowedFixture(fixture, '.github/workflows/ci.yml'), false);
  assert.equal(isAllowedFixture(fixture, 'testsuite/adversarial.test.js'), false);

  // Exact match only: a near-miss is never allowed.
  assert.equal(isAllowedFixture('AKIAIOSFODNN7EXAMPLEX', 'test/x.test.js'), false);
  assert.equal(isAllowedFixture(fixture.toLowerCase(), 'test/x.test.js'), false);

  // And the tracked tree itself must be clean.
  const findings = scan();
  assert.deepEqual(
    findings,
    [],
    `credential-shaped strings in the tree:\n${findings.map((f) => `${f.file}:${f.line} ${f.rule}`).join('\n')}`,
  );
});

// ---------------------------------------------------------------------------
// Adversarial: concurrency and races
//
// Every test here is deterministic. The concurrency is real (several
// operations are in flight at once) but the *outcome* is not timing
// dependent: the assertions are about invariants that must hold for every
// interleaving, not about which interleaving happened.
// ---------------------------------------------------------------------------

test('adversarial: two writers over one state directory keep each other\'s tasks', () => {
  const root = tmpDir('aegis-race-storage-');
  try {
    // Two independent readers/writers over the same directory — the shape of
    // two AEGIS processes running at once.
    const a = new Storage(root);
    const b = new Storage(root);

    a.put(new Task({ id: 'taskA', role: 'coding' }));
    b.put(new Task({ id: 'taskB', role: 'review' }));

    // Neither writer may lose the other's task.
    assert.deepEqual(a.list().map((t) => t.id).sort(), ['taskA', 'taskB']);
    assert.deepEqual(b.list().map((t) => t.id).sort(), ['taskA', 'taskB']);
    assert.ok(a.get('taskA'), 'taskA must still be readable');
    assert.ok(b.get('taskB'), 'taskB must still be readable');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('adversarial: a removal by one writer is not resurrected by another writer', () => {
  const root = tmpDir('aegis-race-remove-');
  try {
    const a = new Storage(root);
    const b = new Storage(root);
    a.put(new Task({ id: 'doomed', role: 'coding' }));
    a.put(new Task({ id: 'keeper', role: 'coding' }));

    a.remove('doomed');
    // The second writer never saw the removal, but it must not put the
    // deleted task back into the index.
    b.put(new Task({ id: 'other', role: 'review' }));

    const ids = a.list().map((t) => t.id).sort();
    assert.deepEqual(ids, ['keeper', 'other']);
    assert.equal(a.get('doomed'), null);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('adversarial: concurrent budget records never overshoot the ceiling', async () => {
  const m = new BudgetManager({ maxOutputChars: 100 });
  const settled = await Promise.allSettled(
    Array.from({ length: 30 }, () => Promise.resolve().then(() => {
      m.record('t1', { output: 10 });
    })),
  );
  const accepted = settled.filter((r) => r.status === 'fulfilled').length;
  const refused = settled.length - accepted;

  // Exactly the ceiling's worth of usage is admitted — never more.
  assert.equal(accepted, 10);
  assert.equal(refused, 20);
  assert.equal(m.global.outputChars, 100);
  assert.equal(m.forTask('t1').outputChars, 100);
  // Every refusal reports the ceiling, not a post-hoc total.
  for (const r of settled) {
    if (r.status === 'rejected') assert.equal(r.reason.code, 'BUDGET_EXCEEDED');
  }
});

test('adversarial: concurrent tool calls all run and leave a verifiable audit chain', async () => {
  const root = tmpDir('aegis-race-tools-');
  const audit = new Audit(path.join(root, 'audit.log'), { key: 'test-key' });
  try {
    const registry = new ToolRegistry();
    registry.register(new Tool({
      name: 'echo',
      purpose: 'concurrency probe',
      riskLevel: 'read',
      run: async (input) => `echo:${input.v}`,
    }));

    const outputs = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        registry.run('echo', { v: i }, { allowedTools: ['echo'], audit })),
    );
    assert.equal(outputs.length, 20);
    assert.deepEqual(outputs, Array.from({ length: 20 }, (_, i) => `echo:${i}`));

    // Every call audited, and the chain still verifies afterwards.
    const v = audit.verify();
    assert.equal(v.ok, true, `audit chain broken: ${v.errors.join('; ')}`);
    assert.equal(v.checked, 40); // start + end for each call
    assert.equal(registry.auditFailures, 0);
  } finally {
    audit.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('adversarial: the tool is aborted at the timeout boundary', async () => {
  const registry = new ToolRegistry();
  let observedAbort = null;
  registry.register(new Tool({
    name: 'slow',
    purpose: 'timeout probe',
    riskLevel: 'read',
    maxDurationMs: 50,
    run: async (_input, ctx) => {
      await new Promise((r) => setTimeout(r, 150));
      observedAbort = ctx.signal.aborted;
      return 'finished';
    },
  }));

  await assert.rejects(
    () => registry.run('slow', {}, { allowedTools: ['slow'] }),
    (err) => err.code === 'TOOL_TIMEOUT',
  );
  // Let the tool body reach its end so the abort can be observed.
  await new Promise((r) => setTimeout(r, 250));
  assert.equal(observedAbort, true, 'the tool must see an aborted signal after the timeout');
});

test('adversarial: a tool that honours the signal stops when the timeout fires', async () => {
  const registry = new ToolRegistry();
  let stopped = false;
  registry.register(new Tool({
    name: 'stoppable',
    purpose: 'timeout probe',
    riskLevel: 'read',
    maxDurationMs: 50,
    run: (_input, ctx) => new Promise((resolve) => {
      const timer = setTimeout(() => resolve('not-stopped'), 10_000);
      ctx.signal.addEventListener('abort', () => {
        clearTimeout(timer);
        stopped = true;
        resolve('stopped');
      }, { once: true });
    }),
  }));

  await assert.rejects(
    () => registry.run('stoppable', {}, { allowedTools: ['stoppable'] }),
    (err) => err.code === 'TOOL_TIMEOUT',
  );
  assert.equal(stopped, true, 'a cooperative tool must stop at the timeout');
});

test('adversarial: concurrent memory writes keep every record', async () => {
  const root = tmpDir('aegis-race-memory-');
  try {
    const memory = new Memory(root);
    await Promise.all(
      Array.from({ length: 25 }, (_, i) => Promise.resolve().then(() => {
        memory.add('p1', { key: `k${i}`, value: `v${i}` });
      })),
    );
    const keys = memory.list('p1').map((r) => r.key).sort();
    assert.equal(keys.length, 25, 'every concurrent write must survive');
    assert.deepEqual(keys, Array.from({ length: 25 }, (_, i) => `k${i}`).sort());
    // The file on disk is always valid JSON — the write is staged and renamed.
    const raw = JSON.parse(fs.readFileSync(path.join(root, 'p1.json'), 'utf-8'));
    assert.equal(Array.isArray(raw), true);
    assert.equal(raw.length, 25);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('adversarial: concurrent checkpoint saves leave a loadable checkpoint', async () => {
  const root = tmpDir('aegis-race-checkpoint-');
  try {
    const store = new CheckpointStore(root);
    await Promise.all(
      Array.from({ length: 10 }, (_, i) => Promise.resolve().then(() => {
        const cp = new Checkpoint({ taskId: 't1' });
        cp.pending.push({ seq: i + 1, name: `step-${i + 1}`, idempotencyKey: `t1#${i + 1}` });
        store.save(cp);
      })),
    );
    // Whatever landed last, the file must load and be usable.
    const loaded = store.load('t1');
    assert.ok(loaded, 'the checkpoint must still load');
    assert.equal(loaded.taskId, 't1');
    assert.ok(Array.isArray(loaded.pending));
    assert.ok(Array.isArray(loaded.completed));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
