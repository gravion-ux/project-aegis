'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { OfflineProvider, deterministicTransform } = require('../aegis/providers/offline');
const { HttpProvider, extractTextAndUsage } = require('../aegis/providers/http');
const { ProviderRouter, ProviderRegistry } = require('../aegis/providers/registry');
const { ProviderError } = require('../aegis/providers/base');

function startMockLLM(replies) {
  return new Promise((resolve) => {
    let i = 0;
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const reply = replies[i] || replies[replies.length - 1];
        i += 1;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(reply));
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}/` });
    });
  });
}

// ---- OfflineProvider ----

test('offline: name is "offline"', () => {
  const p = new OfflineProvider();
  assert.equal(p.name, 'offline');
});

test('offline: complete returns a deterministic transform of the input', async () => {
  const p = new OfflineProvider();
  const r1 = await p.complete({ messages: [{ role: 'user', content: 'hello' }] });
  const r2 = await p.complete({ messages: [{ role: 'user', content: 'hello' }] });
  assert.equal(r1.text, r2.text, 'same input → same output');
  assert.match(r1.text, /^\[offline:[0-9a-f]{8}\] /);
  assert.equal(r1.model, 'offline');
});

test('offline: usage counts characters, not tokens', async () => {
  const p = new OfflineProvider();
  await p.complete({ messages: [{ role: 'user', content: 'abcd' }] });
  const u = p.usage();
  assert.equal(u.unit, 'chars');
  assert.ok(u.input >= 4);
});

test('offline: empty messages array is rejected', async () => {
  const p = new OfflineProvider();
  await assert.rejects(() => p.complete({ messages: [] }), /non-empty/);
});

test('offline: request without a user message is rejected', async () => {
  const p = new OfflineProvider();
  await assert.rejects(
    () => p.complete({ messages: [{ role: 'system', content: 'x' }] }),
    /no user message/,
  );
});

test('deterministicTransform: stable for the same input', () => {
  assert.equal(deterministicTransform('hello'), deterministicTransform('hello'));
  assert.notEqual(deterministicTransform('hello'), deterministicTransform('world'));
});

// ---- HttpProvider ----

test('http: complete against a local mock returns the reply', async () => {
  const mock = await startMockLLM([{ text: 'mocked answer', usage: { prompt_tokens: 5, completion_tokens: 7, total_tokens: 12 } }]);
  try {
    const p = new HttpProvider({ baseUrl: mock.baseUrl, model: 'test-model', name: 'mock' });
    const r = await p.complete({ messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(r.text, 'mocked answer');
    assert.equal(r.model, 'test-model');
    assert.equal(r.usage.total, 12);
    const u = p.usage();
    assert.equal(u.tokenSource, 'reported');
  } finally {
    mock.server.close();
  }
});

test('http: timeout propagates as a retryable ProviderError', async () => {
  // Start a server that never responds. We close it after the test.
  const server = http.createServer(() => {
    // intentionally empty
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  try {
    const p = new HttpProvider({ baseUrl: `http://127.0.0.1:${port}/`, model: 'test-model', timeoutMs: 50 });
    await assert.rejects(() => p.complete({ messages: [{ role: 'user', content: 'hi' }] }), /timeout/);
  } finally {
    server.close();
  }
});

test('http: server 500 is a retryable error', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(503, { 'content-type': 'text/plain' });
    res.end('overloaded');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  try {
    const p = new HttpProvider({ baseUrl: `http://127.0.0.1:${port}/`, model: 'x', timeoutMs: 1000 });
    await assert.rejects(() => p.complete({ messages: [{ role: 'user', content: 'hi' }] }), /server 503/);
  } finally {
    server.close();
  }
});

test('http: client 400 is a non-retryable error', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(400, { 'content-type': 'text/plain' });
    res.end('bad request');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  try {
    const p = new HttpProvider({ baseUrl: `http://127.0.0.1:${port}/`, model: 'x' });
    await assert.rejects(() => p.complete({ messages: [{ role: 'user', content: 'hi' }] }), /client 400/);
  } finally {
    server.close();
  }
});

test('extractTextAndUsage: handles OpenAI-shaped and Ollama-shaped responses', () => {
  const a = extractTextAndUsage({ choices: [{ message: { content: 'a' } }] }, '{}');
  assert.equal(a.text, 'a');
  const b = extractTextAndUsage({ message: { content: 'b' } }, '{}');
  assert.equal(b.text, 'b');
  const c = extractTextAndUsage({ text: 'c' }, '{}');
  assert.equal(c.text, 'c');
  const d = extractTextAndUsage({}, 'raw body');
  assert.equal(d.text, 'raw body');
});

test('http: usage is marked "estimated" when the upstream omits usage', async () => {
  const mock = await startMockLLM([{ text: 'no usage here' }]);
  try {
    const p = new HttpProvider({ baseUrl: mock.baseUrl, model: 'm' });
    await p.complete({ messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(p.usage().tokenSource, 'estimated');
  } finally {
    mock.server.close();
  }
});

// ---- Router ----

test('router: returns offline by default for "offline"', () => {
  const r = new ProviderRouter({ allowPaid: false });
  const p = r.resolve('offline');
  assert.equal(p.name, 'offline');
});

test('router: paid model is refused unless allowPaid', () => {
  const r = new ProviderRouter({ allowPaid: false });
  assert.throws(() => r.resolve('gpt-4o-mini'), /paid provider for model "gpt-4o-mini" is not enabled/);
});

test('router: paid model is allowed when allowPaid=true and AEGIS_LLM_URL is set', () => {
  const r = new ProviderRouter({ allowPaid: true, env: { AEGIS_LLM_URL: 'http://127.0.0.1:9999/' } });
  const p = r.resolve('gpt-4o-mini');
  assert.equal(p.model, 'gpt-4o-mini');
});

test('router: missing AEGIS_LLM_URL throws an informative error', () => {
  const r = new ProviderRouter({ allowPaid: true, env: {} });
  assert.throws(() => r.resolve('gpt-4o-mini'), /AEGIS_LLM_URL is not set/);
});

test('registry: register / get / list', () => {
  const r = new ProviderRegistry();
  r.register('a', { name: 'a' });
  r.register('b', { name: 'b' });
  assert.equal(r.get('a').name, 'a');
  assert.deepEqual(r.list().sort(), ['a', 'b']);
});
