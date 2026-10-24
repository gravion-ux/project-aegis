'use strict';

/**
 * Orchestrator and specialist agent manifest.
 *
 * The orchestrator enforces:
 *   - per-task limits (max iterations, max wall time, max delegation depth)
 *   - bounded retries
 *   - cooperative cancellation
 *   - output schema validation
 *   - audit logging for every step
 *
 * Each agent declares its purpose, inputs, allowed tools, output
 * schema and resource limits. The orchestrator refuses to run an
 * agent that is not in the manifest.
 */

const { STATES, isTerminal, canTransition } = require('./states');
const { ProviderError } = require('./providers/base');

class OrchestratorError extends Error {
  constructor(message, { code = 'ORCHESTRATOR_ERROR' } = {}) {
    super(message); this.name = 'OrchestratorError'; this.code = code;
  }
}

class Manifest {
  constructor() { this._byRole = new Map(); }
  declare(agent) {
    if (!agent || !agent.role) throw new Error('declare: role required');
    if (this._byRole.has(agent.role)) throw new Error(`declare: agent "${agent.role}" already declared`);
    const required = ['role', 'purpose', 'inputs', 'allowedTools', 'outputSchema', 'resourceLimits'];
    for (const f of required) {
      if (!(f in agent)) throw new Error(`declare: agent "${agent.role}" missing field "${f}"`);
    }
    this._byRole.set(agent.role, agent);
    return agent;
  }
  get(role) { return this._byRole.get(role) || null; }
  list() { return [...this._byRole.keys()]; }
}

// ---- built-in agent declarations (handlers are wired in the
// orchestrator itself) ----

const BUILTIN_AGENTS = [
  {
    role: 'coding',
    purpose: 'Run a deterministic coding-style task (classifier / echo / fail).',
    inputs: { type: 'object', properties: { text: { type: 'string' } } },
    allowedTools: ['echo', 'hash.sha256'],
    outputSchema: {
      type: 'object',
      properties: { status: { enum: ['SUCCEEDED', 'FAILED'] }, output: {}, evidence: { type: 'array' } },
      required: ['status', 'output', 'evidence'],
    },
    resourceLimits: { maxIterations: 1, maxWallMs: 5_000, maxDelegationDepth: 0 },
  },
  {
    role: 'review',
    purpose: 'Read a text input and emit a structured review.',
    inputs: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] },
    allowedTools: ['hash.sha256'],
    outputSchema: {
      type: 'object',
      properties: {
        status: { enum: ['SUCCEEDED', 'FAILED'] },
        output: { type: 'object', properties: { score: { type: 'number' }, summary: { type: 'string' }, blockers: { type: 'array' }, nits: { type: 'array' } } },
        evidence: { type: 'array' },
      },
      required: ['status', 'output', 'evidence'],
    },
    resourceLimits: { maxIterations: 1, maxWallMs: 5_000, maxDelegationDepth: 0 },
  },
  {
    role: 'memory',
    purpose: 'Write the input into project memory as a fact.',
    inputs: { type: 'object', properties: { projectId: { type: 'string' }, key: { type: 'string' }, value: {}, tags: { type: 'array' } }, required: ['projectId', 'key', 'value'] },
    allowedTools: [],
    outputSchema: {
      type: 'object',
      properties: {
        status: { enum: ['SUCCEEDED', 'FAILED'] },
        output: { type: 'object', properties: { id: { type: 'string' } } },
        evidence: { type: 'array' },
      },
      required: ['status', 'output', 'evidence'],
    },
    resourceLimits: { maxIterations: 1, maxWallMs: 5_000, maxDelegationDepth: 0 },
  },
  {
    role: 'research',
    purpose: 'Run a single read-only tool call and return a short summary.',
    inputs: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
    allowedTools: ['http.get', 'hash.sha256'],
    outputSchema: {
      type: 'object',
      properties: {
        status: { enum: ['SUCCEEDED', 'FAILED'] },
        output: { type: 'object', properties: { status: { type: 'number' }, snippet: { type: 'string' } } },
        evidence: { type: 'array' },
      },
      required: ['status', 'output', 'evidence'],
    },
    resourceLimits: { maxIterations: 1, maxWallMs: 10_000, maxDelegationDepth: 0 },
  },
  {
    role: 'router',
    purpose: 'Inspect a task input and return the recommended agent role.',
    inputs: { type: 'object' },
    allowedTools: [],
    outputSchema: {
      type: 'object',
      properties: { status: { enum: ['SUCCEEDED', 'FAILED'] }, output: { type: 'object' }, evidence: { type: 'array' } },
      required: ['status', 'output', 'evidence'],
    },
    resourceLimits: { maxIterations: 1, maxWallMs: 1_000, maxDelegationDepth: 0 },
  },
];

/**
 * Conservative declaration used for any registered agent that has no explicit
 * entry in BUILTIN_AGENTS.
 *
 * The defaults are deliberately restrictive: no tools at all, one iteration,
 * a short wall clock and no delegation. An agent only earns capability by
 * being declared explicitly above — the manifest is an allowlist, so a role
 * that appears here by fallback still runs, but it runs with nothing.
 */
function synthesiseDeclaration(role) {
  return {
    role,
    purpose: `Registered agent "${role}" with no explicit manifest entry; running with default restrictions.`,
    inputs: { type: 'object' },
    allowedTools: [],
    outputSchema: {
      type: 'object',
      properties: {
        status: { enum: ['SUCCEEDED', 'FAILED'] },
        output: {},
        evidence: { type: 'array' },
      },
      required: ['status', 'output', 'evidence'],
    },
    resourceLimits: { maxIterations: 1, maxWallMs: 5_000, maxDelegationDepth: 0 },
    __synthesised: true,
  };
}

function buildDefaultManifest(agentRegistry = null) {
  const m = new Manifest();
  // deep clone each declaration so callers can mutate a manifest without
  // corrupting the shared BUILTIN_AGENTS template
  for (const a of BUILTIN_AGENTS) {
    m.declare(JSON.parse(JSON.stringify(a)));
  }

  // Every registered agent must be runnable. Without this, a Phase 1 role
  // such as `doctor` or `fail` — which has a handler but no explicit entry
  // above — would be rejected with AGENT_NOT_DECLARED the moment someone
  // routed a task to it. Deriving from the registry makes the two lists
  // self-consistent instead of two hand-maintained sets that can drift.
  const registry = agentRegistry || require('./agent').buildDefaultRegistry();
  for (const role of registry.list()) {
    if (!m.get(role)) m.declare(synthesiseDeclaration(role));
  }
  return m;
}

// ---- orchestrator ----

class Orchestrator {
  constructor({ manifest, agentRegistry, toolRegistry, memory, budget, audit, providerRouter, parentDepth = 0 }) {
    this.manifest = manifest || buildDefaultManifest();
    this.agentRegistry = agentRegistry;
    this.toolRegistry = toolRegistry;
    this.memory = memory;
    this.budget = budget;
    this.audit = audit;
    this.providerRouter = providerRouter;
    this.parentDepth = parentDepth;
  }

  /**
   * Run a single task end-to-end. The task already has its role
   * declared. The orchestrator:
   *   - looks up the agent in the manifest and the runtime registry
   *   - enforces declared resource limits
   *   - validates the output against the declared schema
   *   - records audit events
   *
   * Does not mutate the task's state machine; the caller (router)
   * is responsible for the lifecycle.
   */
  async run(task, opts = {}) {
    const declared = this.manifest.get(task.role);
    if (!declared) {
      throw new OrchestratorError(`agent "${task.role}" is not declared in the manifest`, { code: 'AGENT_NOT_DECLARED' });
    }
    const agent = this.agentRegistry && this.agentRegistry.get(task.role);
    if (!agent || typeof agent.run !== 'function') {
      throw new OrchestratorError(`agent "${task.role}" has no implementation registered`, { code: 'AGENT_NO_RUNNER' });
    }

    // Resource limits
    const limits = declared.resourceLimits || {};
    const maxIterations = Math.max(1, Math.min(opts.maxIterations || limits.maxIterations || 1, 10));
    const maxWallMs = Math.max(100, Math.min(opts.maxWallMs || limits.maxWallMs || 5_000, 600_000));
    const maxDelegationDepth = Math.max(0, Math.min(opts.maxDelegationDepth || limits.maxDelegationDepth || 0, 5));

    if (this.parentDepth > maxDelegationDepth) {
      throw new OrchestratorError(
        `delegation depth ${this.parentDepth} exceeds limit ${maxDelegationDepth} for "${task.role}"`,
        { code: 'DELEGATION_LIMIT' },
      );
    }

    // Cooperative cancellation signal
    const signal = opts.signal || new AbortController().signal;
    if (signal.aborted) {
      throw new OrchestratorError('aborted before start', { code: 'ABORTED' });
    }

    const start = Date.now();
    const audit = (kind, payload) => { if (this.audit) try { this.audit.append({ kind, ...payload }); } catch {} };

    audit('orchestrator.start', { taskId: task.id, role: task.role, maxIterations, maxWallMs });

    let lastResult = null;
    let lastError = null;
    let iterations = 0;

    // The budget is a gate, not just an accounting note. Before each
    // attempt the current state is checked, so a task cannot start work
    // when the budget is already exhausted, and a retry loop cannot run
    // past a limit that the budget is meant to enforce.
    //
    // The budget may be a plain Budget or a BudgetManager. A manager
    // enforces the global budget and the task's own budget together, so
    // it is addressed by task id.
    const isManager = !!(this.budget && typeof this.budget.forTask === 'function');
    const budgetGuard = () => {
      if (!this.budget) return;
      if (typeof this.budget.guard === 'function') {
        if (isManager) this.budget.guard(task.id); else this.budget.guard();
        return;
      }
      if (this.budget.global && typeof this.budget.global.guard === 'function') this.budget.global.guard();
    };
    const budgetRecord = (usage) => {
      if (!this.budget) return;
      if (isManager) { this.budget.record(task.id, usage); return; }
      if (typeof this.budget.record === 'function') { this.budget.record(usage); return; }
      if (this.budget.global && typeof this.budget.global.record === 'function') this.budget.global.record(usage);
    };

    while (iterations < maxIterations) {
      if (signal.aborted) {
        audit('orchestrator.aborted', { taskId: task.id, iterations });
        throw new OrchestratorError('aborted mid-run', { code: 'ABORTED' });
      }
      if (Date.now() - start > maxWallMs) {
        audit('orchestrator.timeout', { taskId: task.id, iterations });
        throw new OrchestratorError(`maxWallMs ${maxWallMs} exceeded`, { code: 'TIMEOUT' });
      }
      try {
        budgetGuard();
      } catch (err) {
        audit('orchestrator.budget_exceeded', { taskId: task.id, iterations });
        throw err;
      }
      iterations += 1;

      try {
        const result = await agent.run(task, {
          tools: this.toolRegistry,
          memory: this.memory,
          budget: this.budget,
          providerRouter: this.providerRouter,
          allowedTools: declared.allowedTools,
          signal,
        });
        validateOutput(declared.outputSchema, result);
        // Every attempt is charged, including the successful one. The
        // attempt count is what bounds retries.
        try {
          budgetRecord({ input: 0, output: JSON.stringify(result.output || '').length, tokens: null, attempt: true });
        } catch (err) {
          audit('orchestrator.budget_exceeded', { taskId: task.id });
          throw err;
        }
        audit('orchestrator.end', { taskId: task.id, iterations, status: result.status });
        return result;
      } catch (err) {
        lastError = err;
        if (err instanceof ProviderError && err.retryable && iterations < maxIterations) {
          // Charge the failed attempt before retrying, so the budget sees
          // the real cost of the retry loop rather than only the final
          // successful call.
          try { budgetRecord({ input: 0, output: 0, tokens: null, attempt: true }); }
          catch (budgetErr) {
            audit('orchestrator.budget_exceeded', { taskId: task.id, iterations });
            throw budgetErr;
          }
          audit('orchestrator.retry', { taskId: task.id, iterations, error: err.message });
          continue;
        }
        audit('orchestrator.error', { taskId: task.id, iterations, error: String(err && err.message || err) });
        throw err;
      }
    }

    throw new OrchestratorError(`exhausted ${maxIterations} iterations`, { code: 'EXHAUSTED' });
  }
}

function validateOutput(schema, result) {
  if (!schema || !result) return;
  if (schema.required) {
    for (const f of schema.required) {
      if (!(f in (result || {}))) {
        throw new OrchestratorError(`output missing required field "${f}"`, { code: 'SCHEMA_VIOLATION' });
      }
    }
  }
  if (schema.properties && schema.properties.status && schema.properties.status.enum) {
    if (!schema.properties.status.enum.includes(result.status)) {
      throw new OrchestratorError(`output.status "${result.status}" not in enum`, { code: 'SCHEMA_VIOLATION' });
    }
  }
}

module.exports = { Orchestrator, Manifest, OrchestratorError, buildDefaultManifest, synthesiseDeclaration, BUILTIN_AGENTS };
