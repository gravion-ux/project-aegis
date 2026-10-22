'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const AEGIS_ROOT = path.resolve(__dirname, '..');
const CLI = path.join(AEGIS_ROOT, 'aegis', 'cli.js');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 10_000,
    env: { ...process.env, ...(opts.env || {}) },
    cwd: opts.cwd || AEGIS_ROOT,
  });
}

function freshCwd() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-cli-'));
}

test('CLI: --help exits 0 and lists commands', () => {
  const r = run(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /aegis status/);
  assert.match(r.stdout, /aegis tasks create/);
  assert.match(r.stdout, /aegis doctor/);
});

test('CLI: status on a fresh workspace reports zero tasks', () => {
  const cwd = freshCwd();
  const r = run(['status'], { cwd });
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  const j = JSON.parse(r.stdout);
  assert.equal(j.taskCount, 0);
});

test('CLI: agents list returns the default roles', () => {
  const cwd = freshCwd();
  const r = run(['agents', 'list'], { cwd });
  assert.equal(r.status, 0);
  const j = JSON.parse(r.stdout);
  assert.ok(Array.isArray(j.agents));
  assert.ok(j.agents.includes('classifier'));
  assert.ok(j.agents.includes('doctor'));
});

test('CLI: tasks create + tasks run end-to-end', () => {
  const cwd = freshCwd();
  const c = run(['tasks', 'create', '--title', 'audit', '--role', 'classifier',
                 '--goal', 'Check IDOR on /api/orders'], { cwd });
  assert.equal(c.status, 0, `stderr: ${c.stderr}`);
  const created = JSON.parse(c.stdout);
  const id = created.id;

  const r = run(['tasks', 'run', id], { cwd });
  assert.equal(r.status, 0, `stderr: ${r.stderr}; stdout: ${r.stdout}`);
  const finished = JSON.parse(r.stdout);
  assert.equal(finished.state, 'SUCCEEDED');
  assert.ok(finished.output.buckets.includes('object-level-authorization'));
});

test('CLI: tasks cancel transitions to CANCELLED', () => {
  const cwd = freshCwd();
  const c = run(['tasks', 'create', '--title', 'noop', '--role', 'echo', '--goal', 'x'], { cwd });
  const id = JSON.parse(c.stdout).id;
  const r = run(['tasks', 'cancel', id], { cwd });
  assert.equal(r.status, 0);
  const got = JSON.parse(r.stdout);
  assert.equal(got.state, 'CANCELLED');
});

test('CLI: tasks create with unknown role exits 2', () => {
  const cwd = freshCwd();
  const r = run(['tasks', 'create', '--title', 'x', '--role', 'no-such-agent', '--goal', 'x'], { cwd });
  assert.equal(r.status, 2);
  // The router returns the error in the structured output (stdout), not stderr.
  assert.match(r.stdout, /unknown role/);
});

test('CLI: doctor on a fresh (missing dirs) workspace reports missing', () => {
  const cwd = freshCwd();
  const r = run(['doctor'], { cwd });
  assert.equal(r.status, 0);
  const j = JSON.parse(r.stdout);
  assert.equal(j.ok, false);
  assert.ok(Array.isArray(j.missing));
  assert.ok(j.missing.length > 0);
});

test('CLI: tasks list after two creates reports two tasks', () => {
  const cwd = freshCwd();
  run(['tasks', 'create', '--title', 'a', '--role', 'classifier', '--goal', 'a'], { cwd });
  run(['tasks', 'create', '--title', 'b', '--role', 'classifier', '--goal', 'b'], { cwd });
  const r = run(['tasks', 'list'], { cwd });
  assert.equal(r.status, 0);
  const j = JSON.parse(r.stdout);
  assert.equal(j.tasks.length, 2);
});
