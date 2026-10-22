'use strict';

/**
 * Deterministic agent runner (Phase 0–1).
 *
 * The agent is intentionally simple: it takes a Task, looks at the
 * `role` and `input`, runs a deterministic handler, and returns
 * `{ status, output, evidence }`. There is **no LLM call** in this
 * slice. The point is to prove the lifecycle, the storage, the audit
 * log, and the CLI in isolation from network and provider behaviour.
 *
 * To add a real model adapter later, define a function with the same
 * `(task, ctx) => Promise<{ status, output, evidence }>` signature and
 * add it to the registry in `agents/index.js`.
 */

const { STATES } = require('./states');
const specialists = require('./specialists');

class Agent {
  constructor(role, handler) {
    this.role = role;
    this.handler = handler;
  }

  async run(task, ctx = {}) {
    if (!task || task.role !== this.role) {
      throw new Error(`agent role mismatch: expected ${this.role}, got ${task && task.role}`);
    }
    const result = await this.handler(task, ctx);
    if (!result || !result.status) {
      throw new Error('agent handler must return { status, output, evidence }');
    }
    return result;
  }
}

class AgentRegistry {
  constructor() { this._byRole = new Map(); }
  register(agent) {
    if (!agent || !agent.role) throw new Error('agent must have a role');
    this._byRole.set(agent.role, agent);
    return agent;
  }
  get(role) { return this._byRole.get(role) || null; }
  list() { return [...this._byRole.keys()]; }
}

// -------- built-in deterministic handlers (Phase 0–1) --------

const classify = (task) => {
  const text = String((task.input && task.input.text) || task.goal || '');
  const lc = text.toLowerCase();
  const buckets = [];
  if (/\b(idor|bola)\b/.test(lc)) buckets.push('object-level-authorization');
  if (/\b(xss|csrf|injection)\b/.test(lc)) buckets.push('injection');
  if (/\b(auth|login|token|jwt|session)\b/.test(lc)) buckets.push('auth-and-session');
  if (/\b(rate limit|throttl)\b/.test(lc)) buckets.push('rate-limiting');
  if (/\b(header|hsts|csp|cors|cookie)\b/.test(lc)) buckets.push('transport-headers');
  if (buckets.length === 0) buckets.push('general');
  return {
    status: STATES.SUCCEEDED,
    output: { buckets, text: text.slice(0, 200) },
    evidence: [{ kind: 'classification', buckets, at: new Date().toISOString() }],
  };
};

const echo = (task) => ({
  status: STATES.SUCCEEDED,
  output: { received: task.input, goal: task.goal },
  evidence: [{ kind: 'echo', at: new Date().toISOString() }],
});

const doctorAgent = (task) => {
  // Walk the workspace and report missing directories, etc. We
  // deliberately include `docs` here because the Storage / Audit /
  // Memory classes auto-create state/, data/, and logs/ on first use,
  // so they would never be reported missing in practice.
  const fs = require('node:fs');
  const path = require('node:path');
  const root = task.input && task.input.root ? task.input.root : process.cwd();
  const required = ['state', 'data', 'logs', 'docs'];
  const missing = required.filter((d) => !fs.existsSync(path.join(root, d)));
  return {
    status: STATES.SUCCEEDED,
    output: { root, missing, ok: missing.length === 0 },
    evidence: [{ kind: 'doctor', missing, at: new Date().toISOString() }],
  };
};

const failAgent = (task) => ({
  status: STATES.FAILED,
  output: null,
  error: 'forced failure (test agent)',
  evidence: [{ kind: 'forced', at: new Date().toISOString() }],
});

function buildDefaultRegistry() {
  const reg = new AgentRegistry();
  // Phase 1 roles — behaviour is frozen; phase1-compat.test.js asserts it.
  reg.register(new Agent('coding', classify));
  reg.register(new Agent('classifier', classify));
  reg.register(new Agent('echo', echo));
  reg.register(new Agent('doctor', doctorAgent));
  reg.register(new Agent('fail', failAgent));

  // Phase 2 specialists. Registered here — not only in the manifest — because
  // Orchestrator.run() resolves a role through *both* the manifest and this
  // registry. A role that is declared but unregistered fails with
  // AGENT_NO_RUNNER, so keeping both lists in sync is a correctness
  // requirement, not a tidiness one.
  reg.register(new Agent('review', specialists.review));
  reg.register(new Agent('memory', specialists.memory));
  reg.register(new Agent('research', specialists.research));
  reg.register(new Agent('router', specialists.router));

  return reg;
}

module.exports = { Agent, AgentRegistry, buildDefaultRegistry };
