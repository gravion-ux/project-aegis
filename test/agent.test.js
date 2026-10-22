'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Task } = require('../aegis/task');
const { STATES } = require('../aegis/states');
const { Agent, AgentRegistry, buildDefaultRegistry } = require('../aegis/agent');

test('agent: classifier recognises IDOR / XSS / auth / rate-limit', async () => {
  const reg = buildDefaultRegistry();
  const agent = reg.get('classifier');
  const cases = [
    { text: 'Look for IDOR on /api/orders/:id',       want: 'object-level-authorization' },
    { text: 'Test for XSS in search',                 want: 'injection' },
    { text: 'Check JWT validation on /login',         want: 'auth-and-session' },
    { text: 'Verify rate limit on /api/v1/items',     want: 'rate-limiting' },
    { text: 'Inspect CSP and HSTS headers',           want: 'transport-headers' },
  ];
  for (const c of cases) {
    const t = new Task({ role: 'classifier', input: { text: c.text } });
    const r = await agent.run(t, {});
    assert.ok(r.output.buckets.includes(c.want), `expected ${c.want} in ${JSON.stringify(r.output.buckets)} for "${c.text}"`);
    assert.equal(r.status, STATES.SUCCEEDED);
  }
});

test('agent: echo returns the input', async () => {
  const reg = buildDefaultRegistry();
  const t = new Task({ role: 'echo', input: { hello: 'world' } });
  const r = await reg.get('echo').run(t, {});
  assert.deepEqual(r.output.received, { hello: 'world' });
});

test('agent: fail returns FAILED with error', async () => {
  const reg = buildDefaultRegistry();
  const t = new Task({ role: 'fail' });
  const r = await reg.get('fail').run(t, {});
  assert.equal(r.status, STATES.FAILED);
  assert.match(r.error, /forced/);
});

test('agent: doctor agent reports missing required dirs', async () => {
  const reg = buildDefaultRegistry();
  const fakeRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-doctor-'));
  const t = new Task({ role: 'doctor', input: { root: fakeRoot } });
  const r = await reg.get('doctor').run(t, {});
  assert.equal(r.status, STATES.SUCCEEDED);
  assert.ok(r.output.missing.includes('state'), 'state should be reported missing');
  fs.rmSync(fakeRoot, { recursive: true, force: true });
});

test('agent: registry rejects role mismatch', async () => {
  const reg = new AgentRegistry();
  reg.register(new Agent('coding', () => ({ status: 'SUCCEEDED', output: {}, evidence: [] })));
  const t = new Task({ role: 'classifier' });
  const a = reg.get('coding');
  await assert.rejects(() => a.run(t, {}), /role mismatch/);
});

test('agent: handler must return { status, output, evidence }', async () => {
  const a = new Agent('bad', () => ({ foo: 1 }));
  const t = new Task({ role: 'bad' });
  await assert.rejects(() => a.run(t, {}), /must return/);
});
