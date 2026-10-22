'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  Tool, ToolRegistry, ToolError, ToolDeniedError, ToolNotFoundError,
  buildDefaultRegistry, safeEcho, safeHash,
} = require('../aegis/tools/registry');

function tmpAuditSink() {
  const events = [];
  return { events, audit: { append: (e) => events.push(e) } };
}

test('registry: default-deny rejects an unregistered tool', async () => {
  const r = new ToolRegistry();
  const sink = tmpAuditSink();
  await assert.rejects(
    () => r.run('does.not.exist', {}, { audit: sink.audit }),
    (err) => err instanceof ToolNotFoundError,
  );
  assert.ok(sink.events.find((e) => e.kind === 'tool.deny'));
});

test('registry: per-task allowlist denies tools not on it', async () => {
  const r = buildDefaultRegistry();
  const sink = tmpAuditSink();
  await assert.rejects(
    () => r.run('hash.sha256', { value: 'x' }, { allowedTools: ['echo'], audit: sink.audit }),
    (err) => err instanceof ToolDeniedError,
  );
  assert.ok(sink.events.find((e) => e.kind === 'tool.deny' && e.reason === 'not_in_allowed_tools'));
});

test('registry: allowlist permits and produces the result', async () => {
  const r = buildDefaultRegistry();
  const out = await r.run('hash.sha256', { value: 'abc' }, { allowedTools: ['hash.sha256'] });
  assert.equal(out, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('registry: timeout fires and surfaces a retryable error', async () => {
  const r = new ToolRegistry();
  r.register(new Tool({
    name: 'slow',
    purpose: 'test',
    riskLevel: 'read',
    maxDurationMs: 30,
    run: () => new Promise((r) => setTimeout(r, 200)),
  }));
  const sink = tmpAuditSink();
  await assert.rejects(
    () => r.run('slow', {}, { allowedTools: ['slow'], audit: sink.audit }),
    (err) => err instanceof ToolError && err.code === 'TOOL_TIMEOUT' && err.retryable === true,
  );
  assert.ok(sink.events.find((e) => e.kind === 'tool.call.error'));
});

test('registry: huge output is capped', async () => {
  const r = new ToolRegistry();
  r.register(new Tool({
    name: 'loud',
    purpose: 'returns lots of data',
    riskLevel: 'read',
    maxOutputBytes: 100,
    run: async () => 'x'.repeat(10_000),
  }));
  const out = await r.run('loud', {}, { allowedTools: ['loud'] });
  assert.equal(out.__truncated, true);
});

test('registry: fs.read refuses paths outside the allowlisted root', async () => {
  const r = buildDefaultRegistry();
  const sink = tmpAuditSink();
  const outside = path.resolve(os.tmpdir(), `aegis-outside-${Date.now()}.txt`);
  fs.writeFileSync(outside, 'secret');
  await assert.rejects(
    () => r.run('fs.read', { path: outside }, { allowedTools: ['fs.read'], allowedRoots: [os.tmpdir() + path.sep + 'aegis-only'], audit: sink.audit }),
    /outside allowed roots/,
  );
  fs.unlinkSync(outside);
});

test('registry: fs.read permits paths inside the allowlisted root', async () => {
  const r = buildDefaultRegistry();
  const inside = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-only-'));
  const file = path.join(inside, 'ok.txt');
  fs.writeFileSync(file, 'hello');
  const out = await r.run('fs.read', { path: file }, { allowedTools: ['fs.read'], allowedRoots: [inside] });
  assert.equal(out, 'hello');
  fs.rmSync(inside, { recursive: true, force: true });
});

test('registry: http.get refuses non-loopback URLs', async () => {
  const r = buildDefaultRegistry();
  await assert.rejects(
    () => r.run('http.get', { url: 'http://example.com/' }, { allowedTools: ['http.get'] }),
    /only loopback/,
  );
});

test('registry: tool call emits start + end audit events', async () => {
  const r = new ToolRegistry();
  r.register(safeEcho);
  const sink = tmpAuditSink();
  await r.run('echo', { hi: 1 }, { allowedTools: ['echo'], audit: sink.audit });
  assert.ok(sink.events.find((e) => e.kind === 'tool.call.start'));
  assert.ok(sink.events.find((e) => e.kind === 'tool.call.end'));
});

test('safeHash: empty input produces the empty-string sha256', async () => {
  const out = await safeHash.run({ value: '' }, {});
  assert.equal(out, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});
