'use strict';

/**
 * Phase 1 backward-compatibility guard.
 *
 * These tests prove that everything that worked in Phase 1 still
 * works after the Phase 2 additions. If a Phase 2 change breaks a
 * Phase 1 interface, this file fails loudly.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const aegis = require('../aegis/index');
const CLI = path.join(__dirname, '..', 'aegis', 'cli.js');

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-compat-')); }

// ---- Phase 1 exports still present ----

test('compat: all Phase 1 exports are still exported', () => {
  for (const name of [
    'createContext', 'dispatch', 'help', 'Task', 'Storage', 'Audit',
    'Logger', 'Memory', 'Agent', 'AgentRegistry', 'buildDefaultRegistry',
    'STATES', 'isTerminal', 'canTransition', 'COMMANDS',
  ]) {
    assert.ok(name in aegis, `missing Phase 1 export: ${name}`);
  }
});

test('compat: Phase 2 exports are added', () => {
  for (const name of [
    'OfflineProvider', 'HttpProvider', 'ProviderRegistry', 'ProviderRouter',
    'ToolRegistry', 'buildDefaultTools', 'Budget', 'BudgetManager',
    'Manifest', 'Orchestrator', 'buildDefaultManifest', 'Checkpoint',
    'CheckpointStore', 'Idempotency', 'loadConfig',
  ]) {
    assert.ok(name in aegis, `missing Phase 2 export: ${name}`);
  }
});

// ---- Phase 1 behaviours preserved ----

test('compat: createContext wires the Phase 1 objects', () => {
  const root = tmp();
  const ctx = aegis.createContext({ root });
  assert.ok(ctx.storage);
  assert.ok(ctx.audit);
  assert.ok(ctx.memory);
  assert.ok(ctx.logger);
  ctx.audit.close();
  fs.rmSync(root, { recursive: true, force: true });
});

test('compat: createContext now also wires Phase 2 objects', () => {
  const root = tmp();
  const ctx = aegis.createContext({ root });
  for (const k of ['toolRegistry', 'providerRegistry', 'providerRouter', 'config', 'budgets', 'manifest', 'orchestrator', 'checkpoints']) {
    assert.ok(ctx[k], `createContext did not wire: ${k}`);
  }
  ctx.audit.close();
  fs.rmSync(root, { recursive: true, force: true });
});

test('compat: the state machine is unchanged', () => {
  assert.ok(aegis.canTransition(aegis.STATES.QUEUED, aegis.STATES.READY));
  assert.equal(aegis.canTransition(aegis.STATES.SUCCEEDED, aegis.STATES.RUNNING), false);
});

test('compat: the deterministic agents still behave the same', async () => {
  const registry = aegis.buildDefaultRegistry();
  const t = new aegis.Task({ role: 'classifier', input: { text: 'Look for IDOR on /api/orders/:id' } });
  const r = await registry.get('classifier').run(t, {});
  assert.equal(r.status, aegis.STATES.SUCCEEDED);
  assert.ok(r.output.buckets.includes('object-level-authorization'));
});

test('compat: the default manifest still declares the Phase 1 agent roles', () => {
  const m = aegis.buildDefaultManifest();
  for (const role of ['coding', 'doctor', 'echo', 'fail']) {
    assert.ok(m.get(role), `manifest lost role: ${role}`);
  }
});

// ---- Phase 1 CLI behaviour preserved ----

test('compat: CLI --help still exits 0 and lists Phase 1 commands', () => {
  const r = spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf-8', timeout: 10_000 });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /aegis status/);
  assert.match(r.stdout, /aegis tasks create/);
});

test('compat: CLI tasks create + run still works end-to-end', () => {
  const root = tmp();
  const c = spawnSync(process.execPath, [CLI, 'tasks', 'create', '--title', 'compat', '--role', 'classifier', '--goal', 'IDOR'], {
    encoding: 'utf-8', timeout: 10_000, cwd: root,
  });
  assert.equal(c.status, 0, c.stderr);
  const created = JSON.parse(c.stdout);
  const r = spawnSync(process.execPath, [CLI, 'tasks', 'run', created.id], { encoding: 'utf-8', timeout: 10_000, cwd: root });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).state, 'SUCCEEDED');
  fs.rmSync(root, { recursive: true, force: true });
});

test('compat: CLI unknown command still exits 2', () => {
  const r = spawnSync(process.execPath, [CLI, 'definitely-not-a-command'], { encoding: 'utf-8', timeout: 10_000 });
  assert.equal(r.status, 2);
});

test('compat: Phase 2 CLI commands are routed', () => {
  for (const args of [['providers', 'list'], ['tools', 'list'], ['usage'], ['security', 'scope'], ['config', 'show']]) {
    const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf-8', timeout: 10_000 });
    assert.equal(r.status, 0, `${args.join(' ')} exited ${r.status}: ${r.stderr}`);
    assert.doesNotThrow(() => JSON.parse(r.stdout), `${args.join(' ')} did not emit JSON`);
  }
});