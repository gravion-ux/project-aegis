'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Orchestrator, Manifest, OrchestratorError, buildDefaultManifest, BUILTIN_AGENTS } = require('../aegis/orchestrator');
const { AgentRegistry, buildDefaultRegistry } = require('../aegis/agent');
const { buildDefaultRegistry: buildTools } = require('../aegis/tools/registry');
const { Task } = require('../aegis/task');

function mkOrchestrator(opts = {}) {
  return new Orchestrator({
    manifest: opts.manifest || buildDefaultManifest(),
    agentRegistry: opts.agentRegistry || buildDefaultRegistry(),
    toolRegistry: opts.toolRegistry || buildTools(),
    memory: opts.memory || null,
    budget: opts.budget || null,
    audit: opts.audit || null,
    providerRouter: opts.providerRouter || null,
    parentDepth: opts.parentDepth || 0,
  });
}

test('orchestrator: runs a declared agent to success', async () => {
  const o = mkOrchestrator();
  const t = new Task({ role: 'coding', input: { text: 'check IDOR' } });
  const r = await o.run(t);
  assert.equal(r.status, 'SUCCEEDED');
  assert.ok(Array.isArray(r.output.buckets));
});

test('orchestrator: refuses an agent that is not declared in the manifest', async () => {
  const m = new Manifest();
  const o = mkOrchestrator({ manifest: m });
  const t = new Task({ role: 'coding' });
  await assert.rejects(() => o.run(t), (err) => err.code === 'AGENT_NOT_DECLARED');
});

test('orchestrator: refuses an agent with no runner registered', async () => {
  const o = mkOrchestrator({ agentRegistry: new AgentRegistry() });
  const t = new Task({ role: 'coding' });
  await assert.rejects(() => o.run(t), (err) => err.code === 'AGENT_NO_RUNNER');
});

test('orchestrator: output schema violation is rejected', async () => {
  const m = buildDefaultManifest();
  // deliberately break the declared enum for 'coding'
  const declared = m.get('coding');
  declared.outputSchema.properties.status.enum = ['SUCCEEDED_ONLY'];
  const o = mkOrchestrator({ manifest: m });
  const t = new Task({ role: 'coding', input: { text: 'x' } });
  await assert.rejects(() => o.run(t), (err) => err.code === 'SCHEMA_VIOLATION');
});

test('orchestrator: delegation depth limit is enforced', async () => {
  const o = mkOrchestrator({ parentDepth: 5 });
  const t = new Task({ role: 'coding', input: { text: 'x' } });
  await assert.rejects(() => o.run(t), (err) => err.code === 'DELEGATION_LIMIT');
});

test('orchestrator: pre-aborted signal stops before start', async () => {
  const o = mkOrchestrator();
  const t = new Task({ role: 'coding', input: { text: 'x' } });
  const ac = new AbortController();
  ac.abort();
  await assert.rejects(() => o.run(t, { signal: ac.signal }), (err) => err.code === 'ABORTED');
});

test('orchestrator: mid-run abort is honoured between iterations', async () => {
  const m = buildDefaultManifest();
  m.get('coding').resourceLimits.maxIterations = 5;
  const ac = new AbortController();
  const agents = buildDefaultRegistry();
  const { Agent } = require('../aegis/agent');
  // The agent aborts the shared signal on its first call. The orchestrator
  // must notice at the top of the *next* iteration and stop.
  let calls = 0;
  agents.register(new Agent('coding', async (task, ctx) => {
    calls += 1;
    if (calls === 1) ac.abort();
    return { status: 'SUCCEEDED', output: { buckets: ['general'] }, evidence: [] };
  }));
  const o = mkOrchestrator({ manifest: m, agentRegistry: agents });
  const t = new Task({ role: 'coding', input: { text: 'x' } });
  // first iteration succeeds → returns before the abort is observed, which
  // is correct: cancellation is cooperative, checked between iterations.
  await o.run(t, { signal: ac.signal });
  assert.equal(calls, 1, 'must not loop after a successful iteration');
});

test('orchestrator: abort between iterations stops the run', async () => {
  const m = buildDefaultManifest();
  m.get('coding').resourceLimits.maxIterations = 5;
  const ac = new AbortController();
  const agents = buildDefaultRegistry();
  const { Agent } = require('../aegis/agent');
  // always fail with a retryable provider error so the loop keeps going,
  // then abort on the second call
  const { ProviderError } = require('../aegis/providers/base');
  let calls = 0;
  agents.register(new Agent('coding', async () => {
    calls += 1;
    if (calls === 2) ac.abort();
    throw new ProviderError('transient', { retryable: true });
  }));
  const o = mkOrchestrator({ manifest: m, agentRegistry: agents });
  const t = new Task({ role: 'coding', input: { text: 'x' } });
  await assert.rejects(() => o.run(t, { signal: ac.signal }), (err) => err.code === 'ABORTED');
  assert.equal(calls, 2);
});

test('orchestrator: maxWallMs timeout is enforced', async () => {
  const m = buildDefaultManifest();
  m.get('coding').resourceLimits.maxWallMs = 1;
  const agents = buildDefaultRegistry();
  const { Agent } = require('../aegis/agent');
  const { ProviderError } = require('../aegis/providers/base');
  // each attempt sleeps past the wall clock, then throws retryable so the
  // loop continues and the wall-clock check trips on the next iteration
  agents.register(new Agent('coding', async () => {
    await new Promise((r) => setTimeout(r, 30));
    throw new ProviderError('slow', { retryable: true });
  }));
  const o = mkOrchestrator({ manifest: m, agentRegistry: agents });
  const t = new Task({ role: 'coding', input: { text: 'x' } });
  await assert.rejects(() => o.run(t, { maxIterations: 20 }), (err) => err.code === 'TIMEOUT');
});

test('orchestrator: audit events are emitted', async () => {
  const events = [];
  const o = mkOrchestrator({ audit: { append: (e) => events.push(e) } });
  const t = new Task({ role: 'coding', input: { text: 'x' } });
  await o.run(t);
  assert.ok(events.find((e) => e.kind === 'orchestrator.start'));
  assert.ok(events.find((e) => e.kind === 'orchestrator.end'));
});

test('orchestrator: budget exhaustion is surfaced', async () => {
  const { Budget } = require('../aegis/usage');
  const budget = new Budget({ maxOutputChars: 1 });
  const o = mkOrchestrator({ budget });
  const t = new Task({ role: 'coding', input: { text: 'x' } });
  await assert.rejects(() => o.run(t), (err) => err.code === 'BUDGET_EXCEEDED');
});

test('manifest: declares all builtin agents with required fields', () => {
  const m = buildDefaultManifest();
  for (const a of BUILTIN_AGENTS) {
    const d = m.get(a.role);
    assert.ok(d, a.role);
    for (const f of ['purpose', 'inputs', 'allowedTools', 'outputSchema', 'resourceLimits']) {
      assert.ok(f in d, `${a.role} missing ${f}`);
    }
  }
});