# Project AEGIS — Technical Design (Phase 0–2)

This document describes the architecture that exists in code today. It is
meant to be read alongside the source, not instead of it: every claim here
has a test behind it, and the file that implements it is named.

The organising idea is that an agent system is a **capability system**. An
agent may not do anything that was not declared for it, and every action it
does take must be bounded, attributed, and recoverable.

## Goals

1. A real, runnable CLI (`aegis status | agents | tasks | memory | doctor |
   providers | tools | usage | security | config`).
2. A real task lifecycle with explicit, validated state transitions and
   file-backed storage.
3. Real structured logs and an append-only, HMAC-chained audit trail.
4. An agent runtime where every capability is declared, scoped, limited and
   audited.
5. A suite that exercises all of it, including the adversarial cases.

## Non-goals (deferred to later phases)

- A model-backed agent that replaces the deterministic specialists
  (Phase 3).
- Kali / offensive-security connectors (Phase 4).
- Web dashboard (Phase 5).
- Browser, file ingestion, messaging connectors (Phase 5–7).
- Desktop / mobile packaging (Phase 8).

## Module map

```
aegis/
  index.js              public API; createContext() wires every service
  cli.js                command-line entry point
  router.js             command parser + dispatcher
  task.js               Task model
  states.js             canonical state machine
  storage.js            JSON-file task store
  audit.js              append-only audit log
  log.js                structured logger (JSON lines)
  redact.js             secret redaction
  memory.js             persistent memory
  agent.js              Agent + AgentRegistry, Phase 1 agents
  specialists.js        Phase 2 specialist agents
  orchestrator.js       Manifest + Orchestrator
  usage.js              Budget + BudgetManager
  recovery.js           Checkpoint, Idempotency, cancellation
  config.js             typed config, secret stripping
  providers/
    base.js             provider interface
    offline.js          deterministic provider
    http.js             generic HTTP provider
    registry.js         ProviderRegistry + ProviderRouter
  tools/
    registry.js         Tool + default-deny ToolRegistry
```

## Task lifecycle

```
QUEUED ──▶ READY ──▶ RUNNING ──▶ SUCCEEDED
             │          │   │
             │          │   ├─▶ FAILED ──▶ RETRYING ──▶ RUNNING
             │          │   ├─▶ CANCELLED
             │          │   └─▶ BLOCKED
             │          └─▶ WAITING_FOR_APPROVAL ──▶ RUNNING
             ├─▶ CANCELLED
             └─▶ BLOCKED
```

`states.js` is the only place that defines the lifecycle. `canTransition`
answers the question; `assertTransition` throws `INVALID_TRANSITION` on a
no. `Task.transition()` is the only way to mutate a task's state, and it
appends `{ts, from, to, note, actor}` to `task.transitions` and bumps
`updatedAt`.

`RETRYING` is reachable **only** from `FAILED`. A task cannot jump from
`RUNNING` straight into a retry, so a failing agent cannot spin without
ever recording a failure. `SUCCEEDED` and `CANCELLED` are terminal sinks.

## Storage

State is persisted in `state/<taskId>.json` (one file per task) plus a
sharded index in `state/_index.json`. Writes go through a per-process
mutex (in-process only) — a multi-process lock is a later phase.

A corrupt index is recovered rather than fatal: the loader falls back to
an empty index and keeps the per-task files, so one damaged file cannot
take down the workspace.

## Memory

`aegis/memory.js` stores project-scoped records in
`data/memory/<projectId>.json`. A record carries `id`, `projectId`, an
optional `taskId`, `key`, `value`, `type`, `tags`, `confidence`,
`verifiedBy`, `sourceTaskId`, `ts` and an optional `ttlMs`.

- **Validation.** Every record is checked against the required field set
  before it is used. Records that fail are **quarantined**, not loaded —
  one bad line on disk cannot poison the working set.
- **The key is identity.** `key` is the dedup and lookup identity, so a
  missing key is rejected at the API boundary (`memory.add: key is
  required`) and at the schema layer (`missing field: key`). Normalising a
  missing key would store the literal string `"undefined"` and silently
  collapse every keyless write onto one record.
- **Dedup.** An exact key/value match is a no-op. A near-equal value under
  the same key merges when the caller asks for it (`onNearDuplicate:
  'merge'`): tags union, the longer value wins. A genuinely different
  value under the same key keeps both.
- **Retention.** `ttlMs` sets an expiry; expired records are pruned on
  read.
- **Checkpoints.** `saveCheckpoint` / `loadCheckpoint` capture objective,
  completed work, pending work, decisions, errors and next actions.
- **Context assembly.** `assembleContext` returns the relevant records,
  the latest checkpoint, and an explicit split of **verified**
  (`fact`/`evidence`/`decision`) from **assumption** and **unresolved**.
  The split is the point: a model must never read an open question as a
  settled fact.
- **Redaction.** The redactor runs before any record reaches disk.

## Providers

`aegis/providers/` defines one interface — `name`, `capabilities`,
`complete({model, messages})`, `usage()`, `pricing()` — with two
implementations.

- **offline** — deterministic. The same prompt always yields the same
  response, and it identifies itself as `offline` so no test can mistake it
  for a real model. Usage is reported in characters.
- **http** — POSTs `{model, messages}` to a URL read from
  **`AEGIS_LLM_URL`**, with an optional auth header from
  **`AEGIS_LLM_AUTH_HEADER`**. Neither comes from a committed config file
  or a command-line argument. It can be pointed at a local Ollama,
  LM Studio or llama.cpp endpoint.

`ProviderRouter` resolves a model name to a provider and enforces the
rule that matters: **a paid provider is never silently substituted.** A
model name matching `/gpt-|claude-|gemini-|command-/` is treated as paid;
unless `provider.allowPaid` is explicitly `true`, the router **throws** a
`ProviderError` rather than quietly returning the offline provider. A
silent substitution would produce output that looks like a model answer
and is not one.

Every provider call has a timeout (default 30s) and a bounded retry count
(default 1).

## Tools

`aegis/tools/registry.js` is the single place a capability can exist. A
tool declares `name`, `purpose`, `inputSchema`, `requiredPermissions`,
`riskLevel` (`read` < `mutate` < `external` < `destructive`),
`maxDurationMs` and `maxOutputBytes`.

`ToolRegistry.run(name, input, ctx)` applies five checks in order:

1. **Default-deny** — an unregistered tool throws `ToolNotFoundError`.
2. **Per-task allowlist** — `ctx.allowedTools` must include the name, or
   the call is denied with `ToolDeniedError`.
3. **Risk ceiling** — `ctx.maxRiskLevel` caps the tool's risk level.
4. **Timeout** — enforced with a race; a timeout surfaces a retryable
   `ToolError`.
5. **Output cap** — oversized output is truncated and marked
   `__truncated`.

Every call emits `tool.call.start`, `tool.call.end`, `tool.call.error` or
`tool.deny`. Audit failures never break a tool call.

The default set is `echo`, `hash.sha256`, `fs.read` and `http.get`.
`fs.read` is rooted to an explicit `allowedRoots` list and refuses any
path outside it. `http.get` refuses any non-loopback host. **There is no
shell tool in the registry.**

## Agents, manifest and orchestration

An agent declares, in the manifest: `role`, `purpose`, `inputs`,
`allowedTools`, `outputSchema` and `resourceLimits` (`maxIterations`,
`maxWallMs`, `maxDelegationDepth`). Declaring an agent missing any of
those fields throws.

`Orchestrator.run()` resolves the role through **both** the manifest and
the runtime registry, then enforces the declared limits, validates the
result against the declared output schema, and retries only when the
failure is a `ProviderError` with `retryable` set.

The manifest is **derived from the runtime registry**, so the two cannot
drift. A role that is registered but not explicitly declared receives a
deliberately restrictive fallback: no tools, one iteration, a short wall
clock, no delegation. Capability is something an agent earns by being
declared.

Nine agents are registered: the five Phase 1 ones (`coding`,
`classifier`, `echo`, `doctor`, `fail`) and the four Phase 2 specialists
(`review`, `memory`, `research`, `router`). The specialists are
deterministic and explainable — `review` scores against explicit, named
rules; `router` matches against explicit intent patterns and always
returns a role with a stated reason.

## Resource management

`aegis/usage.js` provides `Budget` (`record`, `wouldExceed`, `exceeded`,
`summary`) and `BudgetManager` (per-task budgets, a global budget, an
aggregate summary). `wouldExceed` is a *preflight* check, so the cost can
be refused before it is incurred rather than after.

Pricing is never invented. With no `pricing` block configured, the report
shows `unknown`.

`aegis/config.js` loads and validates the configuration and strips any
field whose name matches `/token|secret|password|api[_-]?key|
authorization/i`, so a credential cannot be echoed into a log or a status
report.

## Cancellation, checkpoints and recovery

- **Cooperative cancellation.** The orchestrator takes an `AbortSignal`
  and checks it at the top of every iteration, so a run stops between
  steps rather than mid-write.
- **Checkpointing.** `Checkpoint` tracks plan steps (`nextPending`,
  `markCompleted`, `markInterrupted`); `CheckpointStore` persists it.
- **Idempotency.** `Idempotency` records completed step keys; re-running
  a step with a recorded key is a no-op.
- **Resume.** `buildPlanFromTask` reconstructs the plan from a persisted
  task and `detectInterrupted` identifies a run that stopped mid-plan.

The recovery test spawns two real Node child processes against the same
state directory: the first runs two of five steps and exits, the second
runs the remaining three. The test asserts that **no step executes
twice**.

## Audit and logs

The audit log is append-only and HMAC-chained; the runtime exposes
`append` and `read` only. Structured logs are JSON lines, and the
patterns `/(token|api[_-]?key|secret|password)\s*[:=]\s*([^\s"',]+)/gi`
and `/Bearer\s+[A-Za-z0-9._\-]+/g` are replaced with `[REDACTED]` before
writing.

## Failure handling

- The CLI exits non-zero on any uncaught error.
- `aegis doctor` walks the workspace and reports missing directories.
- A corrupt memory file or storage index is recovered, not fatal.
- Tool audit failures never break the tool call.
- A corrupt checkpoint marks the task `BLOCKED` with a recovery-required
  message rather than guessing.

## Tests

173 tests across 16 files, run by `node --test`:

| area | file |
| --- | --- |
| state machine | `test/states.test.js` |
| task model | `test/task.test.js` |
| storage round-trip, corrupt index | `test/storage.test.js` |
| audit chain | `test/audit.test.js` |
| redaction patterns | `test/redact.test.js` |
| Phase 1 agents | `test/agent.test.js` |
| Phase 1 memory interface | `test/memory.test.js` |
| CLI surface | `test/cli.test.js` |
| memory schema, dedup, retention, context assembly | `test/memory2.test.js` |
| providers, routing, paid refusal | `test/providers.test.js` |
| tool permissions | `test/tools.test.js` |
| budgets | `test/usage.test.js` |
| manifest and limits | `test/orchestrator.test.js` |
| cancellation, checkpoint, resume | `test/recovery.test.js` |
| Phase 1 compatibility | `test/phase1-compat.test.js` |
| regression pins for the defects found in Phase 2 | `test/regressions.test.js` |

CI runs the suite on Node 18, 20 and 22, plus the Phase 1 compatibility
suite, an offline provider smoke check, `aegis doctor`, and a credential
scan. The provider URL and auth header are explicitly empty in CI, so it
can never reach a model or echo a secret.

## Open items for Phase 3

- Replace the deterministic specialists with model-backed handlers behind
  the same `Agent` interface, keeping the current tests as the offline
  contract.
- Provider-specific adapters (Anthropic `system` block, OpenAI
  function-calling) rather than one generic HTTP/JSON shape.
- Context compaction for long-running tasks.
- A real web-search capability, explicitly permissioned and scoped, rather
  than the loopback-only `http.get` used today.
