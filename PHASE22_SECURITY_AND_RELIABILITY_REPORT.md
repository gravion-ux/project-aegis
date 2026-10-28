# Project AEGIS — Phase 2.2 Security and Reliability Audit

**Repository:** <https://github.com/gravion-ux/project-aegis>
**Branch:** `phase-2.2-reliability`
**Baseline audited:** [`PHASE22_BASELINE.md`](./PHASE22_BASELINE.md) (commit `1f43f9e`)
**Audited:** 2026-10-25

**Scope:** the Phase 2 implementation and its interaction with Phase 1 —
storage, checkpoints, recovery, persistent memory, the tool registry and its
permissions, budgets, the HTTP provider, the orchestrator, redaction and the
audit trail — plus the CI pipeline that guards them.

**Method.** Every suspected defect was reproduced against the **unmodified**
tree before a line was changed. A finding was recorded only when a probe and
the source agreed. Every fix is pinned by a named regression test.

**Result:** **36 findings** — 20 high, 13 medium, 3 low — all reproduced
before the fix and all regression-tested afterwards. 294 tests, 293 pass,
0 fail, 1 skipped on the Windows audit host; the Linux CI runner executes the
skip.

> **A passing suite is not a security property.** All 36 defects were live
> while the baseline suite was fully green. The suite did not fail — it never
> exercised the path.

> **Seven of the findings (P22-30 … P22-36) were found by the CI runner, not
> by the audit.** The first publication of this branch was **red on Linux**:
> two tests failed that passed on the audit host. The cause was a fix in this
> report that was correct on Windows and wrong on Linux — it detected a
> filename collision by asking the *filesystem*, and only a case-insensitive
> filesystem reports one. Chasing that down exposed the same defect in six
> further places, all of which could destroy or leak another task's or
> project's records. The full account is in
> [CI results](#ci-results).

---

## Scoreboard

| severity | count | status |
| -------- | ----- | ------ |
| Critical | 0 | — |
| High | 20 | fixed, regression-tested |
| Medium | 13 | fixed, regression-tested |
| Low | 3 | fixed, regression-tested |
| **Total** | **36** | **fixed** |

**Files changed:** 17 modified, 5 added, 0 removed. **Dependencies added: 0.**

---

## Workstream verdicts

| workstream | verdict | note |
| ---------- | ------- | ---- |
| **2.2A** baseline | **PASS** | The pre-modification state was captured in [`PHASE22_BASELINE.md`](./PHASE22_BASELINE.md) before any edit: git state, runtime, package info, every test and CI-equivalent command, and the Phase 2.1 finding map. |
| **2.2B** adversarial / fuzz | **PASS** | `test/adversarial.test.js` — 35 deterministic tests. Seeded LCG, fixed corpus, no network except a `127.0.0.1` mock server, no wall-clock dependence. |
| **2.2C** concurrency / races | **PARTIAL** | In-process concurrency is fully exercised (writers, budgets, tools, memory, checkpoints, audit chain). **True multi-*process* concurrency was not tested** — no second OS process was run against one state directory. A lock file is still absent, so a truly simultaneous write can still race. |
| **2.2D** tool permissions | **PASS** | Allowlist shape, risk ceiling, input schema, cancellation, timeout and output caps all enforced in the execution layer and pinned by tests. |
| **2.2E** memory / checkpoint / recovery | **PARTIAL** | Shape validation, version validation, atomic writes and task scoping are fixed and tested. **Crash recovery is fault-injected at the file level, not by killing a process mid-write** — no real crash was induced. |
| **2.2F** provider reliability | **PARTIAL** | Deadlines, redirects, schemes, aborts, usage accounting and error redaction are fixed and tested against a local mock server. **No real LLM endpoint was exercised.** |
| **2.2G** resource limits / observability | **PASS** | Budgets, attempt ceilings, output caps, response caps and hard deadlines all hold. Audit failures are now counted rather than swallowed. |
| **2.2H** dependencies / CI | **PASS** | Zero runtime dependencies confirmed; no lockfile to drift; CI runs every new suite via `npm test`. The first matrix run failed on Linux and the failure was diagnosed to a platform-dependent fix — see [CI results](#ci-results); the matrix is green after the follow-up. |

Two workstreams are **PARTIAL** because of what could *not* be exercised, not
because something failed. The reasons are stated in [Not tested](#not-tested).

---

## High severity

### P22-12 — A string `allowedTools` bypassed the allowlist by substring match

**File:** `aegis/tools/registry.js` (`ToolRegistry.run`)

The allowlist was checked with `String.prototype.includes`:

```js
const allowed = ctx.allowedTools.includes(name);
```

With a string on the left-hand side, `'xechox'.includes('echo')` is `true`.
A caller that passed `allowedTools` as a string instead of an array had their
per-task tool restriction silently downgraded to a substring match. Any tool
name that happened to appear inside the string was permitted.

**Reproduced:** `allowedTools: 'xechox'` permitted a call to the `echo` tool,
which was not named in the allowlist.

**Fix:** the allowlist must be an array. Anything else is an empty allowlist,
which denies everything. `Array.isArray(ctx.allowedTools) ? ctx.allowedTools : []`.

**Test:** `P22-12: an allowlist that is not a list allows nothing` ·
`adversarial: no allowlist shape can permit an undeclared tool`

### P22-13 — A tool's declared `inputSchema` was never enforced

**File:** `aegis/tools/registry.js` (`ToolRegistry.run`)

Tools declare an `inputSchema`, but nothing validated the input against it.
`hash.sha256` declared `{ type: 'object', required: ['data'] }` and accepted
`{}`.

**Reproduced:** `registry.run('hash.sha256', {})` succeeded.

**Fix:** `validateInput()` enforces the JSON-Schema subset the declarations
actually use — `type`, `required` and per-property `type` — and refuses with
`TOOL_INPUT_INVALID`. An absent or empty schema accepts anything, so a tool
that declares no schema keeps its previous behaviour.

**Test:** `P22-13: a tool input that violates its own schema is refused` ·
`adversarial: a tool never runs with an input its schema forbids`

### P22-14 — An invalid `maxRiskLevel` granted the *most permissive* ceiling

**File:** `aegis/tools/registry.js` (`ToolRegistry.run`)

```js
if ((RISK_RANK[tool.riskLevel] || 0) > (RISK_RANK[maxRisk] || 4)) { ... }
```

An unrecognised `maxRiskLevel` — a typo, `null` handled elsewhere, an object —
resolved to `4`, the **highest** rank. The effect of a malformed ceiling was
the opposite of a malformed ceiling: it removed the ceiling.

**Reproduced:** `maxRiskLevel: 'external '` (trailing space) or
`maxRiskLevel: {}` allowed a `destructive` tool.

**Fix:** the ceiling must be a known level; anything else is denied with
`TOOL_DENIED` and an `invalid_max_risk` audit event.

**Test:** `P22-14: an unknown risk ceiling is refused instead of granting the highest` ·
`adversarial: an unknown risk ceiling never grants a permissive ceiling`

### P22-15 — The default risk ceiling was `destructive`

**File:** `aegis/tools/registry.js` (`DEFAULT_MAX_RISK`)

With no `maxRiskLevel` given, the ceiling defaulted to `destructive` — the
highest level. A task that said nothing about risk got the most permissive
policy possible.

**Fix:** the default is now `external`, the highest level any shipped tool
carries. No built-in tool changes behaviour. A `destructive` tool must now be
opted into explicitly.

> **Behaviour change for operators.** If you register a `destructive` tool and
> relied on the old implicit ceiling, pass `maxRiskLevel: 'destructive'`
> explicitly. This is a deliberate tightening, not a regression.

**Test:** `P22-15: a destructive tool does not run under the default ceiling` ·
`adversarial: a destructive tool needs an explicit risk ceiling`

### P22-27 — The audit chain key was a published constant

**File:** `aegis/audit.js`

The HMAC chain was keyed with the literal `aegis-default-audit-key`, present
in the repository. Anyone who had read the source could forge a chain that
verified perfectly. The chain detected *accidental* corruption, not
tampering by anyone who had seen the code.

**Fix:** the key resolves in order — `opts.key` → `AEGIS_AUDIT_KEY` → a
per-process `crypto.randomBytes(32)`. `keyIsPersistent` records whether the
key is stable across restarts, and `verify()` reports it as `authenticated`.

> **Migration note.** Audit logs written by an earlier build were signed with
> the published constant. `verify()` against them now fails unless the old
> key is supplied explicitly. This is expected: the old chains were never
> authenticated in any meaningful sense.

**Test:** `P22-27: the audit chain key is not a published constant` ·
`adversarial: the secret scanner allowlist is scoped to test files`

### P22-28 — The audit chain was never verified at runtime

**File:** `aegis/audit.js`

`Audit` exposed `append` and `read` but no way to check the chain. The
integrity property existed on paper only; `test/audit.test.js` documented
chain verification as a *manual* check.

**Fix:** a new `verify()` method recomputes every hash and checks every
`prev` link, returning `{ ok, checked, errors, authenticated }`.

> `read()` was deliberately **not** changed. The existing Phase 1 test asserts
> that a tampered record is still *read back* — filtering it out would have
> silently altered established behaviour. `verify()` is additive and opt-in.

**Test:** `P22-28: the audit chain can be verified and detects tampering`

### P22-29 — A second writer silently erased the first writer's indexed tasks

**File:** `aegis/storage.js` (`Storage.put`, `Storage.remove`, `Storage.list`, `Storage.get`)

The task index was loaded once in the constructor and then rewritten wholesale
from that in-memory snapshot on every write. Two writers over one state
directory therefore clobbered each other.

**Reproduced:**

```js
const a = new Storage(dir);
const b = new Storage(dir);
a.put(new Task({ id: 'taskA' }));
b.put(new Task({ id: 'taskB' }));
// on-disk index: { tasks: { taskB } }   ← taskA is gone
// files on disk:  taskA.json, taskB.json, _index.json
```

`taskA.json` survived on disk but vanished from the index. `list()` and
`get('taskA')` could never find it again — **silent data loss with no error
and no log line**. This is not an exotic multi-process scenario: it is what
happens when two AEGIS processes run against the same state directory, and
it reproduced with two objects in a single process.

**Fix:** the index write path is now read-modify-write against a **freshly
read** copy of the on-disk index, exactly as `Memory` already did. Only the
key being changed is touched, so a stale writer cannot resurrect a task
another writer removed. Reads refresh from disk as well, so a long-lived
instance does not serve a stale listing.

**Test:** `P22-29: a second writer over the same state directory does not lose the first writer's tasks` ·
`P22-29b: a removal by one writer is not resurrected by another writer` ·
`adversarial: two writers over one state directory keep each other's tasks` ·
`adversarial: a removal by one writer is not resurrected by another writer`

> **What this does not fix.** The read-modify-write is still not atomic across
> *simultaneous* writes. Two processes that write at exactly the same instant
> can still lose one index entry (the task file itself survives). Closing that
> window needs a lock file, which is a later phase — this fix removes the
> wide, silent, everyday window, not the narrow theoretical one.

### P22-30 … P22-36 — Identifier aliasing destroyed and leaked other records

**Found by:** the CI runner, not the audit. **Files:** `aegis/storage.js`,
`aegis/recovery.js`, `aegis/memory.js`, `aegis/paths.js`

The first publication of this branch was **red on Linux** — two tests failed
that passed on the Windows audit host. The cause was the fix for P22-02 itself.

P22-02 was closed by asking the *filesystem* whether two identifiers reached
the same file:

```js
const existing = this._readTaskFile(file);
if (existing && existing.id != null && existing.id !== task.id) { /* refuse */ }
```

On Windows and macOS that is correct: `Alpha.json` and `alpha.json` are one
file, so reading `alpha.json` returns Alpha's record and the collision is
seen. On Linux they are two separate files, the read returns `null`, the guard
does not fire, and the second task is written as a new file — **no error, no
log, and the behaviour differs from every other platform**. The fix was
correct only on the filesystem it was written on.

The same question — *does this identifier reach a file that belongs to
someone else?* — was being answered by the operating system in six further
places. Chasing the CI failure down turned up all of them. Every one was
reproduced against the **published** code before it was changed:

| id | what happened | consequence |
| -- | ------------- | ----------- |
| **P22-30** | A task id of `_INDEX` resolved to `_index.json` (case-insensitive match) and **overwrote the task index**. The index then listed only `_INDEX`; every previously stored task became invisible to `list()` and `get()`. | whole-index loss |
| **P22-31** | `remove('alpha')` unlinked `Alpha.json` — another task's record — because the two names are one file. | record destroyed |
| **P22-32** | `CheckpointStore.clear('alpha')` unlinked `Alpha.checkpoint.json`, destroying another task's checkpoint and breaking its resume. | checkpoint destroyed |
| **P22-33** | `CheckpointStore.save()` under a case-variant id **overwrote** another task's checkpoint file. | checkpoint destroyed |
| **P22-34** | `Memory` stored projects whose ids differed only by case in one file, so `list('ProjectX')` and `list('projectx')` returned **the same records**. | cross-project record leak |
| **P22-35** | `Memory.loadCheckpoint('projectx')` returned **ProjectX's** checkpoint. | cross-project checkpoint leak |
| **P22-36** | A task id of `x.checkpoint` resolved to `x.checkpoint.json` — **task `x`'s checkpoint file** — and overwrote it. | checkpoint destroyed |

P22-34 and P22-35 are the most serious of the seven: they are not data loss
but **data disclosure across a project boundary**, and they occurred on the
audit host (Windows) with ordinary, unremarkable inputs.

**Fix.** The operating system is no longer asked which names are the same.
AEGIS compares identifiers and filenames itself, so the answer is the same on
Linux, macOS and Windows:

- `paths.js` gains `findFilenameVariant(root, filename)` — a case-insensitive
  name comparison over the directory, independent of the host filesystem.
- `storage.js` compares the index's task ids and the directory's filenames
  against the requested id, and refuses a case-variant id with
  `TASK_ID_CONFLICT`. The index-name check (`_index` / `_INDEX`) is now
  case-insensitive too.
- `storage.js` and `recovery.js` verify **ownership** before overwriting: the
  file at that path must be *this* record's file. A file that cannot be read
  at all is also refused — ownership cannot be established — and
  `remove()` / `clear()` followed by a write is the documented recovery.
- `recovery.js` refuses a case-variant checkpoint id on both `save()` and
  `clear()`.
- `memory.js` refuses a case-variant project id on `add()` and
  `saveCheckpoint()`, and `loadCheckpoint()` serves a checkpoint only to the
  project id recorded inside it.

A deliberately damaged file is still replaceable: a project file that cannot
be parsed is this project's own broken file and is rewritten, while a file
that *parses* but holds a foreign document is refused. That distinction is
pinned by the existing atomic-write test.

**Tests:** `test/phase22-aliasing-regressions.test.js` — 7 tests, one per
finding, named for the finding they pin. Each was verified to **fail against
the published pre-fix code and pass against the fix** (7 failing → 0 failing),
so they are regression tests and not restatements of the fix.

> **Why this section is in a security report and not a changelog.** Every one
> of these seven is a trust-boundary failure: a caller-supplied identifier
> reached a record belonging to a different task or project. The audit's own
> P22-05 rule — *an identifier must mean the same thing on every platform* —
> was implemented for *character* portability but not for *case* portability.
> The CI runner found that gap on a platform the audit never ran on.

### P22-02 — Case-differing ids aliased to one file and destroyed each other

**File:** `aegis/storage.js` (`Storage.put`, `Storage.get`)

On a case-insensitive filesystem `Alpha.json` and `alpha.json` are the same
file. Writing `Alpha` after `alpha` silently destroyed the first task, and
`get('Alpha')` returned the *lower* task.

**Fix:** `put()` refuses a same-file/different-id write with
`TASK_ID_CONFLICT`; `get()` verifies that the id inside the file matches the
id requested and returns `null` otherwise. The behaviour is now identical on
every platform.

**Test:** `P22-02: two ids that resolve to the same file cannot overwrite each other` ·
`adversarial: two ids that collide on a case-insensitive filesystem are refused`

### P22-03 — The task id `_index` resolved to the index file

**File:** `aegis/storage.js` (`Storage.put`)

The index lives at `state/_index.json`, inside the same directory as the task
files. A task whose id was `_index` wrote directly over the index.

**Fix:** `put()` refuses the collision with `INVALID_ID`.
**Test:** `P22-03: a task id cannot resolve to the task index file` ·
`adversarial: a task id cannot collide with the task index`

### P22-04 — A task file could be served under a different task id

**File:** `aegis/storage.js` (`Storage.get`)

`get()` returned whatever was in the file at that path without checking the
id recorded inside it. A file copied under another task's name was returned
as if it belonged to that task.

**Fix:** `get()` reads the file, checks the internal `id`, and returns `null`
on a mismatch.

**Test:** `P22-04: a task file is never served under a different task id`

### P22-01 — A task id of `__proto__` polluted the index and hid the task

**File:** `aegis/storage.js` (`Storage._loadIndex`, `Storage.put`)

The index was a plain `{}`. Assigning `index.tasks['__proto__'] = entry` hit
the inherited `__proto__` setter instead of creating an own property. The task
was written to disk but was invisible to `list()` and `get()` — and the
index's prototype was replaced with attacker-influenced data.

**Fix:** the task map is a null-prototype object (`Object.create(null)`),
built by `emptyIndex()` and `toTaskMap()`.

**Test:** `P22-01: a task id of "__proto__" is stored, listed and retrievable` ·
`adversarial: prototype-named task ids do not pollute the index`

### P22-11 — A task's context carried another task's records

**File:** `aegis/memory.js` (`Memory.assembleContext`)

`assembleContext()` grouped every project record into `verified` / `assumption`
/ `unresolved` / `other` without filtering by task. A context assembled for
task A contained task B's task-scoped records — a cross-task confidentiality
breach in a multi-agent system.

**Fix:** records are filtered through a `scoped()` predicate: project-wide
records (`taskId == null`) belong to every task; records bound to a different
task do not.

**Test:** `P22-11: a task context never contains another task's records` ·
`adversarial: memory context never carries another task's records`

### P22-16 — `fs.read` checked one file and read another (TOCTOU)

**File:** `aegis/tools/registry.js` (`fs.read`)

The size ceiling was enforced with `statSync(abs)` but the bytes were read
from `realAbs` — the symlink-resolved path. Between the two calls the
resolved path could point at a different, larger file, so the size check
described a file that was not the one that was read.

**Fix:** the real path is resolved first, the file is then **opened**, and
the size and type are taken from `fstatSync` on that open descriptor. The
bytes read and the bytes checked are the same file.

**Test:** `P22-16: fs.read checks the size of the file it actually reads` —
verified to **fail** against the pre-fix implementation and pass after it,
by resolving the requested path to an oversized file between the path check
and the read. The Phase 2.1 symlink test `fs.read refuses to follow a symlink
out of the allowed root` complements it and runs on Linux CI.

### P22-25 — The redactor missed the most common credential shapes

**File:** `aegis/redact.js`

`redactString()` covered a narrow set of patterns. It missed AWS access keys,
GitHub classic and fine-grained tokens, Slack tokens, OpenAI and Google keys,
Stripe keys, JWTs, PEM private-key blocks, connection strings with embedded
credentials, `Basic` auth headers, and `Bearer` tokens carrying base64
characters (`+`, `/`, `=`). Object **keys** were not redacted at all.

**Reproduced:** `redactString()` returned an AWS access-key id unchanged,
and likewise for a GitHub token, a Slack token, a JWT and a PEM private-key
block. The credential shapes are deliberately **not** spelled out literally
anywhere in this report — the repository's own credential scanner would (and
does) flag them.

**Fix:** the redactor now covers every credential shape the project's own
`scripts/scan-secrets.js` treats as credential-shaped, plus JWTs, connection
strings and Basic auth. Object keys are redacted as well as values.

**Test:** `P22-25: common credential shapes are redacted` ·
`P22-25b: the labelled secret forms are still redacted` ·
`adversarial: no credential shape survives redaction`

---

## Medium severity

### P22-05 — Identifiers that cannot form a filename on Windows were accepted

**File:** `aegis/paths.js` (`isSafeIdentifier`)

The rules rejected traversal but accepted `>`, `<`, `|`, `*`, `?`, `"`, control
characters and the Windows device names (`CON`, `nul`, `COM1`). The same id
therefore behaved differently per platform — a raw `ENOENT` on Windows
instead of a clean "not found".

**Fix:** `WINDOWS_RESERVED_CHARS`, `CONTROL_CHARS` and `WINDOWS_DEVICE_NAMES`
checks were added. The rule is now portable by construction: *reject
traversal, but never let the same id mean two different things on two
platforms.*

**Test:** `P22-05: identifiers that cannot form a filename on Windows are refused` ·
`adversarial: identifier validation accepts and rejects consistently`

### P22-06 — A refused attempt still charged the global budget

**File:** `aegis/usage.js` (`Budget.wouldExceed`, `BudgetManager.record`)

Phase 2.1's M1/M2 made budget refusal atomic, but `wouldExceed()` did not
mirror `record()`'s `attempts` ceiling. A call refused *by the attempt
ceiling* passed the preflight, was recorded globally, and only then hit the
ceiling — so a refused attempt still moved the global budget. The Phase 2.1
report's claim that "a refusal leaves both untouched" was **false for
attempts**.

**Fix:** `wouldExceed()` takes `attempt` and checks the attempts ceiling
identically to `record()`. Both the global and the per-task budget are
preflighted before either is mutated.

**Test:** `P22-06: a refused attempt does not charge the global budget` ·
`adversarial: a refused budget call leaves every counter untouched` ·
`adversarial: the attempt ceiling is enforced on the task budget too`

### P22-07 / P22-08 / P22-09 — Malformed checkpoints loaded and later crashed

**File:** `aegis/recovery.js` (`Checkpoint.fromJSON`, `Checkpoint` constructor)

A checkpoint whose `completed` or `pending` was not an array, whose `version`
was unsupported, or whose entries were `null` or primitives was **accepted**,
and then failed much later inside the resume path with an unrelated
`TypeError` — far from the file that introduced the corruption.

**Reproduced:** a checkpoint with `completed: 'x'` loaded, and the resume path
threw `Cannot read properties of null (reading 'idempotencyKey')`.

**Fix:** `CheckpointStore.load()` returns `null` for a malformed checkpoint.
`Checkpoint.fromJSON` validates array shape, entry objects and the version;
`SUPPORTED_CHECKPOINT_VERSIONS` is `{1}`; the constructor normalises
collections to arrays. The existing `'missing taskId'` message is preserved.

**Test:** `P22-07: a checkpoint with a non-array collection is rejected` ·
`P22-08: a checkpoint with an unsupported version is rejected` ·
`P22-09: a checkpoint whose entries are not objects are rejected` ·
`P22-09b: a checkpoint that loads can always be used` ·
`adversarial: no malformed checkpoint can crash the resume path`

### P22-10 — A memory write was not atomic, so a crash lost every record

**File:** `aegis/memory.js` (`Memory._writeFile`)

The whole file was rewritten in place on every write. A crash during the
write left a truncated file, and the next read returned **zero** records — the
entire store's history, gone.

**Fix:** the record set is staged to a uniquely named temp file and renamed
into place, which is atomic on every supported platform.

**Test:** `P22-10: a memory write leaves the previous records intact` ·
`adversarial: memory survives a partial write without losing everything`

### P22-17 / P22-18 — Unusable provider usage was recorded as a measured zero

**File:** `aegis/providers/http.js` (`extractTextAndUsage`)

An empty `usage: {}` was recorded as `total: 0` with
`tokenSource: 'reported'` — a measured zero that the server never reported.
A non-numeric counter (`'abc'`) produced `NaN`, which makes every later
comparison false and silently disables the limits.

**Fix:** `readCount()` accepts only finite, non-negative numbers. Unusable
counters are treated as absent, never as zero and never as `NaN`. A new
`usage.reported` flag distinguishes a server-reported counter from an
estimate, and `_tokenSource` follows it.

**Test:** `P22-17: usage that the server did not report is not recorded as a measured zero` ·
`P22-18: a non-numeric usage counter never becomes NaN` ·
`adversarial: a provider never reports an unusable counter as a real number` ·
`adversarial: a provider with no reported usage is labelled estimated`

### P22-19 — A 3xx response body was returned as model output

**File:** `aegis/providers/http.js` (`postJson`)

Redirects were not followed, but they were also not rejected: the redirect
body was handed to the caller as if it were the model's answer.

**Fix:** a 3xx is a `ProviderError` — "redirects are not followed".

**Test:** `P22-19: a redirect response is an error, not model output` ·
`adversarial: a redirect is never resolved as model output`

### P22-20 — A non-HTTP provider scheme was accepted

**File:** `aegis/providers/http.js` (`HttpProvider` constructor, `postJson`)

`baseUrl: 'file:///etc/passwd'` was accepted by the HTTP provider.

**Fix:** the URL is parsed and the scheme must be `http:` or `https:`.

**Test:** `P22-20: a provider URL with a non-http scheme is refused` ·
`adversarial: a non-http provider URL is refused`

### P22-21 — The provider had no total deadline

**File:** `aegis/providers/http.js` (`postJson`)

`req.setTimeout()` covers *inactivity* only. A server that dripped one byte
every few milliseconds kept the request open indefinitely.

**Fix:** a hard total deadline timer was added alongside the socket timeout.

**Test:** `P22-21: a slow response is cut off by a total deadline`

### P22-22 — The provider ignored the caller's `AbortSignal`

**File:** `aegis/providers/http.js` (`postJson`)

A cancelled run did not stop the outbound request.

**Fix:** `request.signal` is honoured, and an abort is reported as
`ABORTED`.

**Test:** `P22-22: an aborted request is stopped and reported` ·
`adversarial: an aborted request stops and reports the abort`

### P22-23 — The orchestrator validated only the top level of an output

**File:** `aegis/orchestrator.js` (`validateOutput`)

`validateOutput()` checked that the declared keys were present and that
`status` was a known enum, then stopped. A nested `output` object that
violated its own schema was accepted.

**Fix:** `validateAgainstSchema()` validates recursively against
`matchesSchemaType()` / `describeValueType()`.

**Test:** `P22-23: a nested output that violates its declared schema is refused`

### P22-24 — Audit append failures were swallowed silently

**File:** `aegis/tools/registry.js` (`ToolRegistry._audit`)

If `audit.append()` threw, the exception was swallowed with no signal
anywhere. A tool call could run with **no audit trail at all**, and nothing
reported it.

**Fix:** the failure is counted in `ToolRegistry.auditFailures`. The tool call
is not broken by a broken audit trail — that remains the right call — but the
gap is no longer invisible.

**Test:** `P22-24: a failed audit append is counted, not swallowed silently` ·
`adversarial: the audit trail reports its own failures`

### P22-26 — Tool inputs were written unredacted into the audit log

**File:** `aegis/tools/registry.js` (`summariseInput`)

This was Phase 2.1 residual risk 6, explicitly deferred. `summariseInput()`
put up to 200 characters of the tool input into the audit event verbatim, so
a secret passed as a tool argument was recorded in the audit log.

**Fix:** `summariseInput()` applies `redactString()` before the value is
written.

**Test:** `P22-26: a credential in a tool input is redacted before it reaches the audit log`

---

## Low severity

### P22-17 / P22-18 — Usage accounting was inaccurate, not unsafe

Covered above under the medium pair. The corrected behaviour matters for
reporting: `tokenSource` is now `'reported'` only when the server actually
reported a usable counter, and is otherwise `'estimated'`.

### P22-05 — Identifiers behaved differently on Linux and Windows

Covered above. The defect was portability, not a security boundary, but a
platform-dependent identifier is a reliability defect wherever the operator
cannot choose the platform.

---

## What the fixes changed

| file | change |
| ---- | ------ |
| `aegis/paths.js` | reject Windows-invalid characters, control characters and device names; **`findFilenameVariant()` — case-insensitive filename comparison that does not depend on the host filesystem** |
| `aegis/storage.js` | null-prototype index; index-file collision refused (case-insensitively); same-file id conflict refused; internal-id check on read; **read-modify-write against the on-disk index**; **case-variant ids refused; ownership verified before an overwrite; `remove()` will not unlink another task's file** |
| `aegis/usage.js` | `wouldExceed()` mirrors `record()` exactly, including the attempts ceiling |
| `aegis/recovery.js` | checkpoint shape, entry and version validation; atomic save with a unique temp name; **case-variant ids refused on `save()` and `clear()`; ownership verified before an overwrite** |
| `aegis/memory.js` | atomic staged write; task-scoped context filtering; **case-variant project ids refused; a checkpoint is served only to the project that wrote it** |
| `aegis/tools/registry.js` | array-only allowlist; input-schema enforcement; risk ceiling must be known; default ceiling `external`; `fs.read` reads through an open descriptor; `auditFailures` counter; redacted input summaries |
| `aegis/providers/http.js` | scheme check; 3xx rejected; hard total deadline; abort honoured; usable-usage accounting with a `reported` flag |
| `aegis/providers/base.js` | `ProviderError` accepts a `code` |
| `aegis/orchestrator.js` | recursive output-schema validation |
| `aegis/redact.js` | full credential-shape coverage; object keys redacted |
| `aegis/audit.js` | key from `opts.key` → `AEGIS_AUDIT_KEY` → per-process random; `keyIsPersistent`; new `verify()` |
| `scripts/scan-secrets.js` | the fixture allowlist is now **scoped to `test/`**; Phase 2.2 fixtures added |
| `package.json` | `test:adversarial` and `test:phase22` scripts; the new suites added to `test` and `test:phase2` |
| `test/adversarial.test.js` | **new** — 35 deterministic adversarial, fuzz and concurrency tests |
| `test/phase22-regressions.test.js` | **new** — 32 named regression tests, one per finding |
| `test/phase22-aliasing-regressions.test.js` | **new** — 7 named regression tests for P22-30 … P22-36 |

No dependency was added. The architecture is unchanged: the same modules, the
same interfaces, the same default-deny posture. `test:phase1` was not
touched.

---

## Test results

### The new suites

| suite | file | tests | result |
| ----- | ---- | ----- | ------ |
| adversarial / fuzz / concurrency | `test/adversarial.test.js` | 35 | 35 pass, 0 fail, 0 skipped |
| Phase 2.2 regressions | `test/phase22-regressions.test.js` | 32 | 32 pass, 0 fail, 0 skipped |
| Phase 2.2 identifier-aliasing regressions | `test/phase22-aliasing-regressions.test.js` | 7 | 7 pass, 0 fail, 0 skipped |
| **Phase 2.2 total** | | **74** | **74 pass, 0 fail** |

The adversarial harness is deterministic by construction: a seeded 32-bit
linear congruential generator, a fixed hostile-identifier corpus, no
wall-clock dependence in generated data, and no network access beyond a
`127.0.0.1` mock server. A failure reproduces exactly.

The regression suites name the finding they pin, so a failure points directly
at the defect they protect.

### The regressions were proved to fail before the fix

A test that passes both before and after a change proves nothing about the
change. The seven aliasing regressions were therefore run against the
**published pre-fix code** (`git archive HEAD` → the `aegis/` tree as it was
on the remote branch) and against the fixed tree:

```
PRE-FIX  (published git HEAD)   tests 7   pass 0   fail 7
POST-FIX (working tree)         tests 7   pass 7   fail 0
```

The same before/after check was run for P22-16 in the first pass of this
audit by temporarily reverting the `fs.read` implementation: the regression
failed, and the temporary revert was immediately undone.

### Full suite

```
npm test
  tests   294
  pass    293
  fail      0
  skipped   1     (the symlink test — Linux-only, verified on CI)
```

### Phase 1 compatibility

```
npm run test:phase1
  tests   56
  pass    56
  fail     0
  skipped  0
```

**No Phase 1 assertion was removed.** `test:phase1` is byte-identical to the
baseline script, and the eight Phase 1 test files are unchanged.

### Phase 2 suite

```
npm run test:phase2
  tests   238
  pass    237
  fail      0
  skipped   1
```

### CI-equivalent checks

| check | command | result |
| ----- | ------- | ------ |
| credential scan | `npm run scan:secrets` | exit 0 — `no credential-shaped strings found (7 known test fixture(s) allowed)` |
| offline provider | `npm run smoke` | exit 0 — provider `offline`, `ok: true` |
| workspace doctor | `node aegis/cli.js doctor` | exit 0 — `ok: true`, `missing: []` |
| CLI help | `node aegis/cli.js --help` | exit 0 |

### A note on the credential scanner

The Phase 2.2 redaction fixtures are credential-*shaped* strings, so they
trip the scanner that guards the tree. Two changes keep the control strict
rather than switching it off:

1. The fixture allowlist is now **scoped to files under `test/`**. The same
   string appearing in `aegis/`, in documentation or in CI config is still a
   finding. The allowlist is matched exactly — a near-miss is never allowed.
2. The allowlist entries are assembled from fragments, so
   `scripts/scan-secrets.js` does not contain the shapes it allowlists and
   cannot flag itself.

This is pinned by `adversarial: the secret scanner allowlist is scoped to
test files`.

### Lint / type checks

**Not configured.** The project has no linter, no type checker and no
formatter in `package.json`, and no ESLint/TypeScript configuration in the
tree. None was run, and none is claimed. `require()` of every module already
parses it.

---

## CI results

### The workflow was not modified

`.github/workflows/ci.yml` is **unchanged**. The connected GitHub App
deliberately refuses writes to `.github/` — the directory that controls what
runs inside the repository — so a workflow edit could not be published. That
turned out to cost nothing: the existing workflow's "Run the full test suite"
step invokes `npm test`, and `npm test` now includes the three new suites. The
matrix therefore executes all 294 tests — the 35 adversarial, the 32 Phase 2.2
regressions and the 7 aliasing regressions — exactly as it would have with
extra named steps.

Three additional scripts are available for anyone who wants to run the suites
in isolation: `npm run test:adversarial`, `npm run test:phase22` (39 tests)
and `npm run test:security`.

### The first publication was red — and the runner was right

The first push of this branch (`67760d4`) **failed on Linux**. All three legs
of the matrix (Node 18, 20, 22) failed at the "Run the full test suite" step
with the same two tests, while the entire suite passed on the Windows audit
host:

```
run 40168325981 (node 18):  tests 287   pass 285   fail 2   skipped 0
  not ok  adversarial: two ids that collide on a case-insensitive filesystem are refused
  not ok  P22-02: two ids that resolve to the same file cannot overwrite each other
```

Both tests asserted that the id pair `Alpha` / `alpha` is refused. The P22-02
fix detected the collision by *reading the file* the second id resolved to —
which reports the other task's record only on a case-insensitive filesystem.
On Linux the two names are separate files, the read returned nothing, the
guard did not fire, and the tests failed. **The audit had shipped a fix whose
correctness depended on the filesystem it was written on.** The CI runner —
running on the one platform the audit host could not be — was the only thing
that caught it.

Diagnosing that failure showed the same question being answered by the
operating system in six further places, every one a way to destroy or leak
another task's or project's records. Those seven findings (P22-30 … P22-36)
are described in the [High severity](#high-severity) section above; the fix
compares identifiers directly and behaves identically on every platform.

### Verified runs

The branch tip is green. The matrix below was executed by GitHub Actions on
Linux for the exact tree that contains every fix in this report — run
**[40491307156](https://github.com/gravion-ux/project-aegis/actions/runs/40491307156)**,
head `fdf24ab`, conclusion **success**.

| job | node | job | conclusion | full suite | Phase 1 suite |
| --- | ---- | --- | ---------- | ---------- | -------------- |
| `test (node 20)` | 20.x | [122145642904](https://github.com/gravion-ux/project-aegis/actions/runs/40491307156/job/122145642904) | success | 294 pass / 0 fail / 0 skipped | 56 pass / 0 fail |
| `test (node 18)` | 18.x | [122145643140](https://github.com/gravion-ux/project-aegis/actions/runs/40491307156/job/122145643140) | success | 294 pass / 0 fail / 0 skipped | 56 pass / 0 fail |
| `test (node 22)` | 22.x | [122145643326](https://github.com/gravion-ux/project-aegis/actions/runs/40491307156/job/122145643326) | success | 294 pass / 0 fail / 0 skipped | 56 pass / 0 fail |

Every number above was read back from the job log, not inferred from a green
badge: each job prints two `node --test` blocks, and both were parsed for
`# tests / # pass / # fail / # skipped`.

On all three legs:

- `# not ok` count: **0**.
- The Linux-only symlink guard passed — `ok 236 - security: fs.read refuses to
  follow a symlink out of the allowed root`.
- The seven aliasing regressions passed — `ok 100` … `ok 106`
  (P22-30 … P22-36).

### Run history for this branch

Each row below is a separate, real workflow run. None was cancelled, skipped
or re-run in place to obtain a green result.

| run | head | conclusion | what that head contained |
| ---- | ---- | ---------- | ------------------------ |
| [40491307156](https://github.com/gravion-ux/project-aegis/actions/runs/40491307156) | `fdf24ab` | success | the complete fix set with the aliasing suite wired into `npm test` — the first run to execute all **294** tests |
| [40491294702](https://github.com/gravion-ux/project-aegis/actions/runs/40491294702) | `f7819d1` | success | the fix set plus the aliasing test file, **not yet** listed in `npm test` — 287 / 287, so the new suite did not yet run in CI |
| [40491283861](https://github.com/gravion-ux/project-aegis/actions/runs/40491283861) | `7ef4c9b` | success | + `aegis/memory.js` |
| [40491275930](https://github.com/gravion-ux/project-aegis/actions/runs/40491275930) | `2516b6e` | success | + `aegis/recovery.js` |
| [40490739787](https://github.com/gravion-ux/project-aegis/actions/runs/40490739787) | `7597e4f` | success | + `aegis/storage.js` |
| [40490733759](https://github.com/gravion-ux/project-aegis/actions/runs/40490733759) | `96b785b` | **failure** | + `aegis/paths.js` only — the shared helper without the storage guard that uses it; the same two case-collision tests failed (287 / 285 / 2) |
| [40168325981](https://github.com/gravion-ux/project-aegis/actions/runs/40168325981) | `67760d4` | **failure** | the first publication of this audit — the same two case-collision tests failed (287 / 285 / 2) |

The `96b785b` failure was an expected consequence of publishing the shared
helper before the guards that use it: the helper alone changed no behaviour,
so the two original Linux failures were still present. It is recorded here
rather than hidden, because a branch history that only ever shows green would
misrepresent how the fix was sequenced and which failures were real.

Publishing this report is a documentation-only change — it touches no source,
test or workflow file — and it triggers one further matrix run on the branch.
That run's conclusion is recorded in the delivery notes accompanying this
report rather than here, because the report cannot cite a run that does not
exist at the moment it is written.

---

## Remaining risks

These are known and **not** fixed.

1. **A tool that ignores the abort signal cannot be force-stopped.** The
   registry aborts the signal and rejects the call, but a tool whose body
   never looks at `ctx.signal` keeps running in-process. This audit proved
   the boundary of the guarantee: the signal *is* delivered at the timeout
   boundary (`adversarial: the tool is aborted at the timeout boundary`), and
   a cooperative tool *does* stop
   (`adversarial: a tool that honours the signal stops when the timeout
   fires`) — but a tool that ignores it runs to completion. This is a
   contract, not an enforcement.
2. **The budget cannot un-spend.** The guard stops *further* work, but the
   attempt that produced an overage still ran to completion. The output size
   is not knowable before the output exists.
3. **Truly simultaneous writers can still race.** The storage index is now
   merged rather than overwritten, which closes the wide window, but two
   processes writing at the same instant can still lose one index entry. A
   lock file is the real fix and remains a later phase.
4. **No multi-process test was run.** The two-writer defect was reproduced
   with two objects in one process, which exercises the same code path but
   not OS-level interleaving, and not a genuine crash.
5. **`Idempotency` is in-memory.** It does not survive a process restart.
   Cross-restart idempotency comes from the persisted checkpoint's
   `completed` list, not from `Idempotency` itself.
6. **The audit chain protects integrity, not confidentiality.** The secret
   lives in the key, not the log.
7. **The audit key is random per process unless `AEGIS_AUDIT_KEY` is set.**
   Such a chain detects corruption within the process lifetime but cannot
   prove authorship later. `verify()` reports this as
   `authenticated: false` rather than pretending otherwise.
8. **Audit logs from earlier builds no longer verify** without the old
   published key. See the migration note under P22-27.
9. **The `memory` specialist trusts `input.projectId`.** It is validated, so
   it cannot escape the memory root, but it can still name any project
   inside it.
10. **`fs.read` is not sandboxed against a hostile filesystem.** The TOCTOU
    gap is closed and the symlink escape was already closed, but a root that
    is itself attacker-controlled is still a root.
11. **`aegis security scope` still reports hard-coded scope information.**
    It prints a static description of the boundary rather than the
    *effective* roots and limits of the current context. A reporting
    inaccuracy, left alone to avoid scope creep.

---

## Not tested

Stated plainly, because a passing suite is not a security property.

1. **No real LLM provider was exercised.** `AEGIS_LLM_URL` is unset and no
   credential is available. The HTTP provider was tested against a local
   mock server only. Its behaviour against Ollama, LM Studio, llama.cpp or a
   hosted API is **unverified**. This is why workstream 2.2F is PARTIAL.
2. **No multi-process concurrency was performed.** No second OS process was
   run against one state directory, and no process was killed mid-write. The
   concurrency tests use two objects in one process. This is why workstream
   2.2C is PARTIAL.
3. **No crash was actually induced.** The atomic-write behaviour was tested
   by fault injection at the file level (a truncated file), not by killing a
   process during a write. This is why workstream 2.2E is PARTIAL.
4. **The symlink escape could not be reproduced on the audit host.**
   Creating a symlink on Windows needs a privilege this account lacks
   (`EPERM`), so the Phase 2.1 test **skips on Windows**. It is executed and
   passed on the Linux CI runner. The Windows skip is an environment
   limitation, not an untested path.
5. **No penetration test of a deployed instance.** This is a source-and-
   behaviour audit, not an adversarial exercise of a running deployment.
6. **No dependency audit was possible.** The project has **zero runtime
   dependencies** and uses only Node built-ins, so there is no third-party
   supply chain to review. The Node.js standard library itself was not
   audited.
7. **No fuzzing beyond the harness.** The harness generates identifiers and
   random strings from a seeded generator and asserts boundary properties.
   It is not a coverage-guided fuzzer and does not explore the whole state
   space of every module.
8. **No linter or type checker ran.** None is configured.
9. **The other repositories in the `gravion-ux` account were not audited.**
   This pass covered `project-aegis` only.

---

## Next steps

1. ~~Capture the baseline before modifying.~~ **Done** —
   [`PHASE22_BASELINE.md`](./PHASE22_BASELINE.md).
2. ~~Reproduce every suspected defect before fixing it.~~ **Done** — 36
   findings, each reproduced against the unmodified (and, for the aliasing
   family, the **published**) tree.
3. ~~Pin every confirmed defect with a regression test.~~ **Done** — 39
   named regression tests plus 35 adversarial tests. The 7 aliasing
   regressions were additionally proved to fail against the published
   pre-fix code.
4. ~~Extend CI with the new suites and verify the matrix.~~ **Done** — and
   the first red matrix run is what exposed findings P22-30 … P22-36.
5. Give `Budget` a real `maxAttempts` in `aegis.config.example.json` so the
   retry bound is on by default rather than merely available.
6. Add a lock file for multi-process state safety, and a real multi-process
   test to close the 2.2C PARTIAL.
7. Document `AEGIS_AUDIT_KEY` in `SECURITY.md` — a persistent key is what
   makes an audit chain verifiable across restarts.
8. Decide whether `Audit.read()` should surface chain-integrity status to
   its callers, or leave verification entirely opt-in.
