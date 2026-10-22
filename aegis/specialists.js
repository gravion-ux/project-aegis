'use strict';

/**
 * Specialist agents (Phase 2D).
 *
 * Phase 1 shipped five deterministic agents (`coding`, `classifier`, `echo`,
 * `doctor`, `fail`). Phase 2 added a manifest with four *specialist*
 * declarations (`review`, `memory`, `research`, `router`) — but until now
 * those roles were declared and then unreachable, because no handler was
 * ever registered for them. `Orchestrator.run()` resolves a role through
 * both the manifest and the runtime registry, so a declared-but-unregistered
 * role fails with `AGENT_NO_RUNNER`.
 *
 * This module closes that gap. Every handler is deterministic and offline:
 * no network call, no LLM call, no clock-dependent branching. They are the
 * same contract as the Phase 1 agents:
 *
 *     handler(task, ctx) -> { status, output, evidence }
 *
 * `ctx` is supplied by the orchestrator and carries `tools`, `memory`,
 * `budget`, `providerRouter`, `allowedTools` and `signal`. A handler must
 * treat `ctx.allowedTools` as the ceiling for anything it calls — the tool
 * registry enforces default-deny independently, but a handler that tries to
 * exceed its declared allowlist is a bug worth surfacing rather than hiding.
 */

const { STATES } = require('./states');

const nowIso = () => new Date().toISOString();

// ---- review ---------------------------------------------------------------

// Patterns that make a change unsafe regardless of context. These are the
// same families the portfolio scanners look for, kept deliberately small and
// explicit so the output is explainable rather than a black-box score.
const BLOCKERS = [
  { id: 'hardcoded-credential', re: /\b(api[_-]?key|secret|password|access[_-]?token)\b\s*[:=]\s*["'][^"']{6,}["']/i, why: 'looks like a hardcoded credential' },
  { id: 'eval', re: /(^|[^.\w])eval\s*\(/, why: 'eval() executes arbitrary code' },
  { id: 'child-process-shell', re: /child_process[\s\S]{0,80}exec(Sync)?\s*\(/, why: 'exec() spawns a shell' },
  { id: 'insecure-tls', re: /rejectUnauthorized\s*:\s*false/, why: 'disables TLS certificate verification' },
];

const NITS = [
  { id: 'todo', re: /\b(TODO|FIXME|XXX)\b/, why: 'unresolved marker left in the body' },
  { id: 'console-log', re: /console\.log\s*\(/, why: 'debug logging left in the body' },
  { id: 'long-line', re: /^.{121,}$/m, why: 'line exceeds 120 characters' },
];

/**
 * Read-only structured review. Scores 100 minus 25 per blocker and 5 per
 * nit, floored at 0. Returns findings as arrays of objects so a caller can
 * act on them without re-parsing prose.
 */
const review = async (task) => {
  const text = String((task.input && task.input.text) || '');
  const lines = text.split('\n');

  const blockers = [];
  for (const b of BLOCKERS) {
    if (b.re.test(text)) blockers.push({ id: b.id, why: b.why });
  }

  const nits = [];
  for (const n of NITS) {
    const hit = lines.some((l) => n.re.test(l));
    if (hit) nits.push({ id: n.id, why: n.why });
  }

  const score = Math.max(0, 100 - 25 * blockers.length - 5 * nits.length);
  const summary = blockers.length
    ? `${blockers.length} blocker(s), ${nits.length} nit(s) — not safe to merge as-is`
    : `no blockers, ${nits.length} nit(s)`;

  return {
    status: STATES.SUCCEEDED,
    output: { score, summary, blockers, nits },
    evidence: [{ kind: 'review', score, blockerIds: blockers.map((b) => b.id), at: nowIso() }],
  };
};

// ---- memory ---------------------------------------------------------------

/**
 * Persist the input into project memory as a typed fact.
 *
 * Secrets are redacted by `Memory.add()` on the way in, so this agent never
 * needs its own scrubber. When no memory store is wired the agent fails
 * loudly rather than silently dropping the write.
 */
const memoryAgent = async (task, ctx = {}) => {
  const input = (task && task.input) || {};
  if (!ctx.memory) {
    return {
      status: STATES.FAILED,
      output: null,
      error: 'no memory store wired into this agent context',
      evidence: [{ kind: 'memory', written: false, reason: 'no_store', at: nowIso() }],
    };
  }
  try {
    const rec = ctx.memory.add(input.projectId, {
      key: input.key,
      value: input.value,
      tags: input.tags,
      type: input.type || 'fact',
    }, { taskId: task.id });

    return {
      status: STATES.SUCCEEDED,
      output: { id: rec.id },
      evidence: [{ kind: 'memory', id: rec.id, key: rec.key, type: rec.type, at: nowIso() }],
    };
  } catch (err) {
    return {
      status: STATES.FAILED,
      output: null,
      error: String((err && err.message) || err),
      evidence: [{ kind: 'memory', written: false, error: String((err && err.message) || err), at: nowIso() }],
    };
  }
};

// ---- research -------------------------------------------------------------

/**
 * One read-only fetch and a short excerpt.
 *
 * The `http.get` tool is loopback-only by construction, so this agent can
 * never be used to reach a third-party host. A denial (tool missing, not in
 * `allowedTools`, non-loopback URL, timeout) is reported as a FAILED result
 * with the reason preserved, because "it was refused" is the useful answer.
 */
const research = async (task, ctx = {}) => {
  const url = task && task.input && task.input.url;
  if (!url) {
    return {
      status: STATES.FAILED,
      output: null,
      error: 'url is required',
      evidence: [{ kind: 'research', fetched: false, reason: 'no_url', at: nowIso() }],
    };
  }
  if (!ctx.tools) {
    return {
      status: STATES.FAILED,
      output: null,
      error: 'no tool registry wired into this agent context',
      evidence: [{ kind: 'research', fetched: false, reason: 'no_tools', at: nowIso() }],
    };
  }

  try {
    const res = await ctx.tools.run('http.get', { url }, {
      allowedTools: ctx.allowedTools || [],
      signal: ctx.signal,
      audit: ctx.audit,
    });
    const body = typeof res === 'string' ? res : JSON.stringify(res);
    return {
      status: STATES.SUCCEEDED,
      output: { status: (res && res.status) || 0, snippet: body.slice(0, 500) },
      evidence: [{ kind: 'research', url, httpStatus: (res && res.status) || 0, at: nowIso() }],
    };
  } catch (err) {
    return {
      status: STATES.FAILED,
      output: null,
      error: String((err && err.message) || err),
      evidence: [{ kind: 'research', url, fetched: false, error: String((err && err.message) || err), at: nowIso() }],
    };
  }
};

// ---- router ---------------------------------------------------------------

const ROUTE_RULES = [
  { role: 'research', re: /\b(fetch|url|http|download|site|endpoint)\b/i, reason: 'input names a remote resource' },
  { role: 'review', re: /\b(review|diff|patch|pr|pull request|lint|refactor)\b/i, reason: 'input asks for a structured review' },
  { role: 'memory', re: /\b(remember|store|note|fact|memor)\b/i, reason: 'input asks to persist a fact' },
  { role: 'doctor', re: /\b(doctor|diagnos|health|check|missing|broken)\b/i, reason: 'input asks for a workspace check' },
];

/**
 * Recommend a specialist role for the input. Deterministic first-match, and
 * it always returns something — an unroutable input falls back to `coding`
 * with an explicit reason rather than returning null and failing upstream.
 */
const routerAgent = async (task) => {
  const text = String((task && task.input && task.input.text) || task.goal || '');
  const match = ROUTE_RULES.find((r) => r.re.test(text));
  const recommended = match ? match.role : 'coding';
  const reason = match ? match.reason : 'no specialist rule matched; defaulted to coding';
  return {
    status: STATES.SUCCEEDED,
    output: { recommended, reason, text: text.slice(0, 200) },
    evidence: [{ kind: 'router', recommended, reason, at: nowIso() }],
  };
};

module.exports = {
  review,
  memory: memoryAgent,
  research,
  router: routerAgent,
  BLOCKERS,
  NITS,
  ROUTE_RULES,
};