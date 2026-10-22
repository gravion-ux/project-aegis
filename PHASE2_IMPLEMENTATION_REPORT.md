# Project AEGIS — Phase 2 Implementation Report

This is the verified ledger of what Phase 2 implemented, what the test
suite actually proves, and what remains blocked. Every number below was
produced by running the suite in this repository — nothing here is
estimated or carried over from a plan.

**Current state: 173 tests, 173 passing, 0 failing.**

## Status legend

- `PASS` — implemented and verified by an automated test in this repo
- `BLOCKED` — the safe interface is implemented and tested, but the real
  integration needs a credential or service unavailable in this environment
- `PARTIAL` — what is done is verified; what remains is listed explicitly

## Scoreboard

| subphase | workstream                                  | status          | tests |
| -------- | ------------------------------------------- | --------------- | ----- |
| 2A       | audit, branch, baseline                      | `PASS`          | 38 (unchanged) |
| 2B       | persistent memory                            | `PASS`          | 19 |
| 2C       | provider abstraction                         | `PASS` (real provider `BLOCKED`) | 17 |
| 2D       | permission-controlled tools                  | `PASS`          | 10 |
| 2D       | resource / budget manager                    | `PASS`          | 10 |
| 2D       | specialist agents + orchestrator             | `PASS`          | 12 + 22 |
| 2E       | cancellation, checkpoint / resume            | `PASS`          | 16 |
| 2E       | CI workflow                                  | `PASS`          | — |
| —        | Phase 1 compatibility suite                  | `PASS`          | 11 |
| —        | Task model suite (new in this pass)          | `PASS`          | 18 |
|          | **total**                                    |                 | **173** |

Per-file counts:

| file | tests | | file | tests |
| ---- | ----- |-| ---- | ----- |
| `test/states.test.js` | 4 | | `test/memory2.test.js` | 19 |
| `test/task.test.js` | 18 | | `test/providers.test.js` | 17 |
| `test/storage.test.js` | 5 | | `test/tools.test.js` | 10 |
| `test/audit.test.js` | 4 | | `test/usage.test.js` | 10 |
| `test/redact.test.js` | 7 | | `test/orchestrator.test.js` | 12 |
| `test/agent.test.js` | 6 | | `test/recovery.test.js` | 16 |
| `test/memory.test.js` | 4 | | `test/phase1-compat.test.js` | 11 |
| `test/cli.test.js` | 8 | | `test/regressions.test.js` | 22 |

## Workstream 1 — Persistent memory (PASS)

`aegis/memory.js` (enhanced in place; the Phase 1 API is preserved)

- **Schema validation** — every record is validated against a required
  field set (`id`, `projectId`, `key`, `value`, `ts`, `type`). Malformed
  records read off disk are quarantined, not loaded into the working set.
- **Project / task separation** — a record carries `projectId` and an
  optional `taskId`; retrieval scopes respect the split.
- **CRUD** — `add`, `get`, `update`, `delete`, `list`.
- **Retrieval** — `search(query, projectId)` scores each record by where
  the query matched: `key` +3, `value` +2, `tags` +1, then sorts by score
  descending and timestamp ascending.
- **Metadata** — `type` (`fact`, `decision`, `assumption`, `unresolved`,
  `evidence`, `preference`), `confidence`, `verifiedBy`, `sourceTaskId`,
  `tags`, `ttlMs`.
- **Deduplication** — an exact key/value match is a no-op. A near-equal
  value under the same key merges (tags union, longer value wins) when the
  caller passes `onNearDuplicate: 'merge'`. A distinct value under the same
  key keeps both.
- **Retention** — `ttlMs` sets an expiry; expired records are pruned on read.
- **Checkpoints** — `saveCheckpoint(projectId, snapshot)` /
  `loadCheckpoint(projectId)`.
- **Context assembly** — `assembleContext({ projectId, taskId, query })`
  returns the relevant records, the latest checkpoint, and an explicit
  split of verified / assumption / unresolved.
- **Secret redaction on write** — the redactor runs before any record
  reaches disk.

## Workstream 2 — Provider abstraction (PASS; real provider BLOCKED)

`aegis/providers/base.js`, `offline.js`, `http.js`, `registry.js`

- `base.js` — the provider interface: `name`, `capabilities`,
  `complete({ model, messages })`, `usage()`, `pricing()`.
- `offline.js` — deterministic provider. The same prompt always yields the
  same response, and it identifies itself as `offline` so no test can
  mistake it for a real model. Usage is reported in characters.
- `http.js` — generic HTTP provider. POSTs `{ model, messages }` to a URL
  read from the **`AEGIS_LLM_URL` environment variable** — never from a
  command-line argument and never from a committed config file. The
  auth header, when needed, comes from `AEGIS_LLM_AUTH_HEADER`. It can be
  pointed at a local Ollama / LM Studio / llama.cpp endpoint.
- `registry.js` — `ProviderRegistry` (routes a model name to a provider,
  refuses unknown models) and `ProviderRouter` (the routing policy).
- **Paid-provider refusal** — a model whose name matches
  `/gpt-|claude-|gemini-|command-/` is treated as paid. The router
  **throws** `ProviderError` rather than silently falling back, unless the
  config sets `provider.allowPaid: true`. The default is `false`.
- **Timeouts and bounded retries** — every provider call has a timeout
  (default 30s) and a bounded retry count (default 1).
- **Usage metadata** — the HTTP provider records the upstream `usage`
  block when one is supplied; the offline provider reports character counts.

**BLOCKED — real provider verification.** No paid API key is available in
this environment and `AEGIS_LLM_URL` is unset. The HTTP provider is
exercised end-to-end by a local mock server in `test/providers.test.js`;
it has never been pointed at a real model. To validate one, set
`AEGIS_LLM_URL` to a local endpoint and run `npm run smoke`.

## Workstream 3 — Specialist agents and orchestrator (PASS)

`aegis/orchestrator.js` (manifest + runner), `aegis/specialists.js` (handlers)

- **Manifest** — every agent declares `role`, `purpose`, `inputs`,
  `allowedTools`, `outputSchema`, `resourceLimits`
  (`maxIterations`, `maxWallMs`, `maxDelegationDepth`). Declaring an
  agent that is missing any of those fields throws.
- **Specialist agents** — `review`, `memory`, `research`, `router`:
  - `review` — reads a text input and emits `{ score, summary, blockers,
    nits }`. Blockers are hardcoded, explainable rules (hardcoded
    credential, `eval()`, `exec()`, `rejectUnauthorized: false`); nits are
    `TODO`/`FIXME`, `console.log`, and over-long lines. Score = 100 − 25
    per blocker − 5 per nit.
  - `memory` — writes the input into project memory as a typed fact and
    returns the record id. Secrets are redacted by the memory layer on the
    way in.
  - `research` — performs a single read-only fetch through the tool
    registry and returns `{ status, snippet }`. The `http.get` tool is
    **loopback-only**, so this agent cannot reach a third-party host. A
    denial is reported as a FAILED result with the reason preserved.
  - `router` — recommends a specialist role by matching the input against
    explicit rules, and always returns a role (falling back to `coding`
    with a stated reason).
- **Orchestrator** — runs an agent under its declared limits: per-task
  wall-clock timeout, iteration cap, delegation-depth cap, output schema
  validation, and bounded retry on a `ProviderError` with `retryable` set.
  Every step emits an audit event.
- **Registry / manifest consistency** — the manifest is derived from the
  runtime agent registry, so a role can never be declared without a runner
  or registered without a declaration. Any role without an explicit entry
  gets a *restrictive* fallback declaration: no tools, one iteration, no
  delegation.

Registered agents (9): `coding`, `classifier`, `echo`, `doctor`, `fail`
(Phase 1) and `review`, `memory`, `research`, `router` (Phase 2).

## Workstream 4 — Resource and budget manager (PASS)

`aegis/usage.js`, `aegis/config.js`

- `Budget` — `record()`, `wouldExceed()`, `exceeded()`, `summary()`.
- `BudgetManager` — per-task budgets via `forTask()`, plus a global
  budget and an aggregate `summary()`.
- **Preflight** — `wouldExceed()` lets the orchestrator check a cost
  *before* making the call. Exceeding the cap throws `BUDGET_EXCEEDED`.
- **Pricing is never invented** — with no `pricing` block configured the
  report shows `unknown`, not a fabricated number.
- **Typed config** — `loadConfig()` / `validateConfig()` with a default
  shape of:
  ```
  provider: { default: 'offline', allowPaid: false, timeoutMs: 30000, maxRetries: 1 }
  budget:   { maxInputChars: null, maxOutputChars: 200000, maxTokens: null, maxCost: null, pricing: null }
  runtime:  { maxIterations: 3, maxWallMs: 60000, maxDelegationDepth: 2, maxRetries: 2 }
  memory:   { retentionMs: null, maxRecordsPerProject: 5000 }
  ```
- **`stripSecrets()`** removes any config field whose name matches
  `/token|secret|password|api[_-]?key|authorization/i`, so a credential
  cannot be echoed back into a log or a status report.

## Workstream 5 — Permission-controlled tools (PASS)

`aegis/tools/registry.js`

- Each tool declares `name`, `purpose`, `inputSchema`,
  `requiredPermissions`, `riskLevel` (`read` < `mutate` < `external` <
  `destructive`), `maxDurationMs`, `maxOutputBytes`.
- **Default-deny** — an unregistered tool throws `ToolNotFoundError`.
- **Per-task allowlist** — a task carries `allowedTools`; a call outside
  that list is denied and audited as `tool.deny`.
- **Risk ceiling** — a task's `maxRiskLevel` caps what it may call.
- **Timeout** — enforced via a race; a timeout surfaces a retryable
  `ToolError`.
- **Output cap** — oversized output is truncated and marked
  `__truncated`.
- **Audit** — `tool.call.start`, `tool.call.end`, `tool.call.error`,
  `tool.deny`. Audit failures never break a tool call.
- **Default toolset (4):** `echo`, `hash.sha256`, `fs.read`, `http.get`.
- **No unrestricted shell.** There is no shell tool in the registry at
  all. `fs.read` is rooted to an explicit `allowedRoots` list and refuses
  any path outside it. `http.get` refuses any non-loopback host. A
  `shell.run` tool would be `destructive` risk and would still be denied
  unless a task explicitly opted in — it has deliberately not been written.

## Workstream 6 — Cancellation, checkpoints, recovery (PASS)

`aegis/recovery.js`

- **Cooperative cancellation** — the orchestrator takes an
  `AbortSignal` and checks it at the top of every iteration, so a run
  stops between steps rather than mid-write.
- **Checkpointing** — `Checkpoint` tracks plan steps (`nextPending()`,
  `markCompleted()`, `markInterrupted()`); `CheckpointStore` persists it
  under the state directory.
- **Idempotency** — `Idempotency` records completed step keys; re-running
  a step with a key already recorded is a no-op.
- **Restart recovery** — `buildPlanFromTask()` reconstructs the plan from
  a persisted task; `detectInterrupted()` identifies a run that stopped
  mid-plan.
- **Verified across a real process boundary** — the recovery test spawns
  two separate Node child processes against the same state directory. The
  first runs two of five steps and exits; the second runs the remaining
  three. The test asserts that **no step is executed twice**.
- `CancellationError` carries the `CANCELLED` code.

## Workstream 7 — Testing and CI (PASS)

- `.github/workflows/ci.yml` — runs on push to `main` and `phase-*` and on
  pull requests to `main`. Node **18, 20, 22** matrix, `fail-fast: false`.
  Steps: checkout → setup-node → install → `npm test` → `npm run
  test:phase1` → offline provider smoke → CLI doctor → credential scan.
- The smoke and doctor steps run with `AEGIS_LLM_URL` and
  `AEGIS_LLM_AUTH_HEADER` explicitly empty, so CI can never make a
  network call to a provider or leak a credential into a log.
- **`scripts/scan-secrets.js`** — scans the tracked tree for
  credential-*shaped* strings (provider key formats, a PEM private key
  header, a long bearer token). The rules are narrow on purpose: a broad
  regex produces false positives on the very fixtures that prove redaction
  works, and a scanner that cries wolf gets deleted. Known synthetic test
  fixtures are allowed by **exact** match — a substring match would let a
  real credential that merely starts with a fixture prefix through. The
  scanner was verified by planting credentials of two different shapes and
  confirming it fails, then removing them and confirming it passes.

## Defects found and fixed in this pass

The suite was at **123/133** when this pass began. Ten failures traced to
one rename; the remaining work surfaced four further defects that the
green-ish suite had been hiding.

1. **`aegis/router.js` referenced `ctx.registry`** (5 call sites) after
   `createContext` renamed the field to `ctx.agentRegistry`. Every CLI
   command that touched agents or ran a task failed with
   `Cannot read properties of undefined (reading 'list')`. Fixed by
   updating the call sites.

2. **`memory.add()` stored a missing key as the literal string
   `"undefined"`.** `normalize()` did `key: String(input.key)`, and
   `String(undefined)` is `"undefined"`. Because `key` is the dedup and
   lookup identity, every keyless write collapsed onto one shared record
   and a missing key was silently accepted. Fixed at two layers: an
   explicit guard at the API boundary (`memory.add: key is required` —
   the exact Phase 1 message) and a schema-level `missing field: key` in
   `validate()`. A previous pass had *loosened* the Phase 1 assertion
   from `/key is required/` to `/key/` to accommodate the bug; that
   assertion has been restored, and `test/memory.test.js` is byte-identical
   to the Phase 1 baseline again.

3. **`buildDefaultManifest()` dropped the Phase 1 roles.** The manifest
   declared `coding`, `review`, `memory`, `research`, `router` while the
   runtime registry held `coding`, `classifier`, `echo`, `doctor`, `fail`.
   Only `coding` was in both. Routing a task to `doctor` failed with
   `AGENT_NOT_DECLARED`. Fixed by deriving the manifest from the runtime
   registry, so the two lists cannot drift again.

4. **The four specialist roles were declared but had no implementation.**
   `review`, `memory`, `research` and `router` existed in the manifest with
   full metadata and no handler, so they failed with `AGENT_NO_RUNNER`.
   Implemented in `aegis/specialists.js` and registered.

5. **`test/task.test.js` was referenced by `package.json` but did not
   exist.** Node's test runner silently ignores a path that does not
   resolve, so every green run had been hiding that the Task model — the
   core state machine — had **no dedicated test file at all**. The file
   was written (18 tests) and the Phase 1 baseline count of 38 was
   unaffected.

`test/regressions.test.js` (22 tests) locks each of these down, so none
can silently return.

## Security and reliability findings

- **No API keys in code, logs, or commits.** Provider configuration is
  environment-only. `stripSecrets()` scrubs credential-shaped config
  fields on read. `aegis.config.json` is gitignored;
  `aegis.config.example.json` is the committed template and states in a
  comment that it must never hold a key.
- **No real LLM call from CI.** The HTTP provider is exercised against a
  local mock; CI runs the offline provider with the provider URL
  explicitly empty.
- **No unrestricted shell.** No shell tool is registered.
- **Default-deny tool registry.** Unknown tool, missing allowlist entry,
  risk ceiling, timeout, and output cap are all enforced and audited.
- **Failure isolation.** A corrupt memory file or storage index is
  recovered cleanly and cannot take down a working task.
- **Process restart covered.** The end-to-end recovery test proves resume
  replays only unfinished steps, across a genuine process boundary.
- **Paid providers are opt-in.** `allowPaid` defaults to `false` and the
  router throws rather than falling back.

## Known limitations

- **No real LLM provider has been verified.** `AEGIS_LLM_URL` is unset and
  no paid key is available. The HTTP provider is proven against a local
  mock only.
- **The provider adapter is generic** (HTTP + JSON). Provider-specific
  quirks — Anthropic's `system` block, OpenAI's function-calling format —
  are not encoded. Adding them is a small follow-up once a credential is
  available.
- **`research` cannot reach the public internet.** It uses the
  loopback-only `http.get` tool by design. A real web-search tool would
  be a separate, explicitly-permissioned tool.
- **The specialists are deliberately simple.** They are deterministic rule
  engines, not model-backed agents. That is what makes Phase 2 testable
  without a credential; it is not a substitute for model-backed behaviour.
- **Phase 3–9 are not started.** This report covers Phase 2 only.

## Next steps

1. **Real provider smoke test** — once `AEGIS_LLM_URL` points at a local
   Ollama / LM Studio endpoint, run `npm run smoke` and add the endpoint
   to the CI matrix.
2. **AEGIS Phase 3 — model-backed specialists.** Replace the deterministic
   handlers behind the same `Agent` interface, keeping the current tests
   as the offline contract.
3. **AEGIS Phase 4 — scoped security tooling.** Port the `scope.js`
   pattern from `webapp-security-toolkit` into `aegis/tools/` as a
   explicitly-permissioned tool with a scope file.
