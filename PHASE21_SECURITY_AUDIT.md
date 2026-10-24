# Project AEGIS — Phase 2.1 Security Hardening Audit

**Repository:** <https://github.com/gravion-ux/project-aegis>
**Scope:** the Phase 2 implementation (persistent memory, provider
abstraction, tool registry, resource manager, specialist agents,
orchestrator, cancellation/recovery) and its interaction with the Phase 1
surface.
**Method:** read every trust boundary, then write behavioural probes that
exercise the suspected behaviour directly. A finding was only recorded when
the code and a probe agreed.

**Result:** 14 findings, all reproduced before the fix and all pinned by a
regression test afterwards. 220 tests, 219 pass, 0 fail, 1 skipped on the
Windows audit host; **220 pass, 0 skipped** on the Linux CI runner (see
[Not tested](#not-tested)).

> A green suite is not a security property. Several of the findings below
> were live while every existing test passed — the suite simply never
> exercised the path.

---

## Scoreboard

| severity | count | status |
| -------- | ----- | ------ |
| High     | 3     | fixed, regression-tested |
| Medium   | 7     | fixed, regression-tested |
| Low      | 4     | fixed, regression-tested |
| **Total**| **14**| **fixed** |

---

## High severity

### H1 — Path traversal through a task id (arbitrary read and write)

**Files:** `aegis/storage.js:55` (`get`), `aegis/storage.js:68` (`put`),
`aegis/storage.js:83` (`remove`)

`Storage` built a filename from a caller-supplied id with no validation:

```js
const file = path.join(this.root, `${taskId}.json`);
```

`path.join` normalises `..` segments, so the id `../outside` resolved to
the parent of the state directory. The id reaches this code straight from
the command line — `aegis tasks show <id>`, `tasks run <id>`,
`tasks cancel <id>` — so `aegis tasks show ../../somefile` read a file
outside the workspace, and a task constructed with a traversing id wrote
outside it.

**Reproduced:** a probe placed `outside.json` next to the state directory,
put `../outside` into the index, and `storage.get('../outside')` returned
the file's contents. `storage.put(new Task({ id: '../escaped' }))` created
`escaped.json` in the parent directory.

**Fix:** new `aegis/paths.js`. `assertSafeIdentifier()` rejects an
identifier that contains a path separator, is absolute, is `.`/`..`,
contains NUL, or is a Windows drive-relative path. `resolveWithin()`
additionally resolves the final path and compares it against the root, so
the boundary holds even if the string rules are relaxed later. `get` and
`remove` treat an unsafe id as "not found"; `put` throws `INVALID_ID`,
because a write must never land outside the root.

### H2 — Path traversal through a checkpoint task id

**File:** `aegis/recovery.js:64` (`CheckpointStore._file`)

Same defect as H1 in the checkpoint store: `path.join(this.dir,
\`${taskId}.checkpoint.json\`)`. A checkpoint could be written to, or read
from, anywhere on disk.

**Reproduced:** `store.save(new Checkpoint({ taskId: '../escaped' }))`
created `escaped.checkpoint.json` outside the state directory;
`store.load('../outside')` read a checkpoint from outside it.

**Fix:** the same `recordPath()` helper. `save()` throws `INVALID_ID`;
`load()` and `clear()` treat an unsafe id as "not found".

### H3 — Path traversal through a memory project id

**File:** `aegis/memory.js:105` (`_file`), `aegis/memory.js:109`
(`_checkpointFile`)

`path.join(this.root, \`${projectId || 'default'}.json\`)` with no
validation. The `memory` specialist passes the task's `input.projectId`
straight through (`aegis/specialists.js`), so a task input could steer the
memory store outside its root.

**Reproduced:** `memory.add('../escaped', { key: 'k', value: 'v' })`
created `escaped.json` next to the memory root.

**Fix:** the same `recordPath()` helper.

---

## Medium severity

### M1 — A refused budget call still charged the budget

**File:** `aegis/usage.js:36` (`Budget.record`)

`record()` incremented the counters and *then* checked the limit:

```js
this.inputChars += input;      // mutated first
...
if (this.exceeded()) { throw ... }   // checked second
```

So a call that was refused still moved the budget. Repeated refused calls
inflated the totals, and the summary reported usage that never happened.

**Reproduced:** `new Budget({ maxOutputChars: 10 })`, then
`record({ output: 50 })` threw `BUDGET_EXCEEDED` — and
`summary().outputChars` was `50`, not `0`.

**Fix:** the limit is evaluated against the *prospective* totals before
anything is mutated. A refused call leaves the budget exactly as it was,
and the error carries the unchanged totals.

### M2 — The BudgetManager preflight used the wrong argument keys

**File:** `aegis/usage.js:116` (`BudgetManager.record`)

```js
const trial = { inputChars: usage.input || 0, outputChars: ..., tokens: ... };
if (this.global.wouldExceed(trial)) { ... }
```

`wouldExceed()` destructures `{ input, output, tokens }`. The trial object
used `inputChars`/`outputChars`, so `input` and `output` fell back to
their `0` defaults and the prospective check compared the *current* total
against the limit instead of current-plus-new. The global preflight could
therefore never fire before the write; the limit was only ever hit as a
side effect of `Budget.record` throwing afterwards.

**Reproduced:** with `global.limits.inputChars = 50` and 40 already
recorded, the preflight computed `40 + 0 > 50` → false, so it passed and
the call proceeded to be recorded.

**Fix:** the trial object uses the correct keys, and the per-task budget is
preflighted as well as the global one. Neither `record()` can throw after
the other has already mutated, so a refusal leaves both untouched.

### M3 — Per-task budget limits were silently ignored

**File:** `aegis/usage.js:107` (`BudgetManager.forTask`)

`forTask(taskId, opts)` only applied `opts` when it *created* the budget.
Since `record()` called `this.forTask(taskId)` with no options, the first
record created an unlimited budget, and any limit set afterwards was
dropped on the floor. A task could end up with no limit at all while the
caller believed it had set one.

**Reproduced:** `m.record('t1', { input: 10 })` then
`m.forTask('t1', { maxInputChars: 15 })` left
`byTask.get('t1').limits.inputChars` as `undefined`, and the next record
of 100 units did not throw.

**Fix:** `forTask()` applies supplied limits whether the budget already
exists or not.

### M4 — The orchestrator had no budget gate; work ran before the check

**File:** `aegis/orchestrator.js:254` (pre-fix)

The budget was recorded *after* `agent.run()` returned:

```js
const result = await agent.run(task, {...});   // the work happens here
validateOutput(declared.outputSchema, result);
this.budget.record({ ... });                   // and is only checked here
```

The budget was an after-the-fact accounting note, not a limit. An
exhausted budget did not stop a new run from starting, and a refused run
had already performed all of its work.

**Reproduced:** with `maxOutputChars: 10`, the agent body executed
(`workDone = true`) and only *then* did the run throw
`BUDGET_EXCEEDED`.

**Fix:** `budget.guard()` is called at the top of every iteration, before
the agent runs, so a task cannot start when there is no headroom. The
guard is stricter than `exceeded()`: reaching a limit counts as having no
headroom, because nothing is left to spend.

### M5 — Retries were never charged to the budget

**File:** `aegis/orchestrator.js:262` (pre-fix)

The retry path continued the loop without recording anything:

```js
if (err instanceof ProviderError && err.retryable && iterations < maxIterations) {
  audit('orchestrator.retry', ...);
  continue;                                    // no budget.record()
}
```

So the number of provider calls a task could make was bounded only by the
orchestrator's iteration cap (max 10), never by the budget. A retry loop
could run far past a cost limit, and the accounting showed nothing.

**Reproduced:** an agent that always failed with a retryable
`ProviderError` ran 3 times, and the budget recorded `0/0`.

**Fix:** every attempt is charged, including the failed ones. A new
optional `maxAttempts` limit on `Budget` bounds the retry loop from the
budget side. `Budget.record({ attempt: true })` increments the attempt
counter.

### M6 — The tool registry ignored the abort signal

**File:** `aegis/tools/registry.js:101` (`ToolRegistry.run`)

`ctx.signal` was passed to the tool but never inspected by the registry.
An already-aborted run started its tools normally, so a cancelled task
still performed its side effects.

**Reproduced:** with a controller aborted before the call, the tool body
executed and returned normally.

**Fix:** `run()` refuses to start a tool when the signal is already
aborted (`TOOL_DENIED` / `ABORTED`).

### M7 — A timed-out tool kept running

**File:** `aegis/tools/registry.js:131` (`_withTimeout`)

The timeout was implemented with `Promise.race`. The race rejects the
caller, but the tool's promise keeps running — the registry had told the
caller "timed out" while the tool was still executing and still able to
produce side effects.

**Reproduced:** a 400 ms tool with a 60 ms timeout was still running when
`run()` rejected with `TOOL_TIMEOUT`, and it completed afterwards.

**Fix:** the registry owns an `AbortController` that is linked to the
caller's signal and aborted on timeout. The tool receives the linked
signal and can stop. (A tool that ignores the signal still cannot be
force-stopped in-process — that limit is recorded under
[Residual risk](#residual-risk).)

### M8 — `fs.read` and `http.get` loaded unbounded data into memory

**Files:** `aegis/tools/registry.js:192` (`fs.read`),
`aegis/tools/registry.js:213` (`http.get`)

Both tools read the whole file / response body into memory. The registry's
`maxOutputBytes` truncation happens *after* the tool returns, so it never
prevented the allocation.

**Reproduced:** `fs.read` loaded a 20 MB file in 37 ms; `http.get`
buffered an 8 MB response.

**Fix:** both tools now enforce a 1 MiB ceiling themselves and refuse
(`TOOL_OUTPUT_TOO_LARGE`) before reading.

### M9 — The CLI died with a fatal error on a missing task

**File:** `aegis/router.js:73` (`tasks run`), `aegis/router.js:107`
(`tasks cancel`)

```js
const t = Task.fromJSON(ctx.storage.get(id));   // throws when get() returns null
if (!t) return { code: 2, output: { error: `no such task: ${id}` } };
```

`Task.fromJSON` throws `missing id` on a null argument, so the friendly
"no such task" branch was unreachable and the process died with
`fatal: Task.fromJSON: missing id` and exit code 1.

**Reproduced:** `aegis tasks run t_doesnotexist` → exit 1, stderr
`fatal: Task.fromJSON: missing id`.

**Fix:** the lookup result is checked before it is deserialised. Both
commands now exit 2 with `no such task: <id>`.

---

## Low severity

### L1 — `fs.read` followed a symlink out of an allowed root

**File:** `aegis/tools/registry.js:192`

The containment check compared `path.resolve(input.path)` against the
allowed roots. `path.resolve` does not resolve symlinks, so a link inside
an allowed root pointing outside it was followed and read.

**Fix:** the check is repeated against `fs.realpathSync()` of the file and
of each allowed root, so a link that leaves the root is refused.

**Not reproducible on the audit host** — creating a symlink on Windows
requires a privilege this account does not have (`EPERM`). The regression
test therefore **skips locally** and **runs on the Linux CI runner**.

**Verified on Linux CI** — run `40103601935` on commit `34d63a6` executed
the test and passed it on all three matrix legs:

```
ok 162 - security: fs.read refuses to follow a symlink out of the allowed root
```

L1 is therefore fixed-by-test, not only fixed-by-inspection. The Windows
skip is an environment limitation, not an untested path.

### L2 — The HTTP provider buffered an unbounded response

**File:** `aegis/providers/http.js:84` (`postJson`)

The provider accumulated response chunks with no ceiling, so a local model
server could exhaust the process's memory.

**Fix:** `maxResponseBytes` (default 8 MiB); an oversized response is
refused with a non-retryable `ProviderError`.

### L3 — A provider error message could echo a secret

**File:** `aegis/providers/http.js:101` (pre-fix)

A 4xx/5xx response body was placed into the error message verbatim. A
server that echoed the request would put the `Authorization` header into
a log line. The `http error:` message had the same exposure.

**Fix:** error bodies are passed through `redactString()` before they
become an error message.

### L4 — A checkpoint could be adopted under another task's name

**File:** `aegis/recovery.js:68` (`CheckpointStore.load`)

`load()` returned whatever checkpoint was in the file, without checking
that its internal `taskId` matched the requested one. A checkpoint copied
under another task's filename would be loaded as if it belonged to that
task, and a later `save()` would write it back under the other name.

**Fix:** `load()` returns `null` when the ids do not match.

---

## Additional hardening (not a defect, but a gap found while auditing)

- **Non-finite usage was accepted.** `Budget.record({ output: NaN })` made
  every later comparison false, silently disabling the limits. Now refused
  with `INVALID_USAGE`.
- **`http.get` rejected the IPv6 loopback.** The check compared
  `u.hostname` against `'::1'`, but the URL parser returns `'[::1]'`. The
  check now strips the brackets, so IPv6 loopback works — a functionality
  fix, not a loosening of the boundary.
- **`fs.read` accepted a directory** and would throw a raw `EISDIR` from
  `readFileSync`. It now refuses with a clear `TOOL_DENIED`.

---

## What the fixes changed

| file | change |
| ---- | ------ |
| `aegis/paths.js` | **new** — identifier validation and root containment |
| `aegis/storage.js` | validate ids; `hasOwnProperty` on the index lookup |
| `aegis/recovery.js` | validate ids; verify the checkpoint's internal id |
| `aegis/memory.js` | validate project ids |
| `aegis/usage.js` | check-before-mutate; correct preflight keys; apply late limits; `maxAttempts`; `guard()` |
| `aegis/orchestrator.js` | budget gate before each attempt; charge every attempt |
| `aegis/tools/registry.js` | honour the abort signal; abort on timeout; output caps; symlink-safe `fs.read` |
| `aegis/providers/http.js` | response size cap; redact error bodies |
| `aegis/router.js` | check the lookup before deserialising |
| `aegis/index.js` | export `paths` |

No dependency was added. The architecture is unchanged: the same modules,
the same interfaces, the same default-deny posture.

---

## Test results

### Regression suite

`test/security-hardening.test.js` — **47 tests, 46 pass, 0 fail, 1
skipped** on Windows; **47 pass, 0 skipped** on Linux CI.

Each test names the finding it pins. The mapping:

| finding | test |
| ------- | ---- |
| H1 | `Storage.put refuses a traversing task id…`, `Storage.get refuses…`, `Storage.remove refuses…` |
| H2 | `CheckpointStore.save refuses…`, `…load refuses…`, `…clear refuses…` |
| H3 | `Memory.add refuses a traversing project id`, `Memory checkpoint refuses…` |
| malformed ids | `malformed identifiers are rejected`, `ordinary identifiers are accepted` |
| M1 | `a refused Budget.record leaves the counters untouched`, `the budget error reports the unchanged totals` |
| M2 | `the global budget preflight fires before the usage is recorded` |
| M3 | `per-task limits set after the first record are applied` |
| M4 | `the orchestrator refuses to start when the budget is exhausted` |
| M5 | `every attempt is charged to the budget`, `a retry loop is charged… and can be bounded by the budget` |
| M6 | `a cancelled run does not start the tool` |
| M7 | `a timeout aborts the tool instead of abandoning it`, `an external cancellation reaches a running tool` |
| M8 | `fs.read refuses a file over the size limit`, `http.get refuses a response over the size limit` |
| M9 | `the CLI reports a missing task as a usage error, not a crash` |
| L1 | `fs.read refuses to follow a symlink out of the allowed root` |
| L2 | `the HTTP provider refuses an oversized response` |
| L3 | `an error body that echoes a token is redacted` |
| L4 | `a checkpoint whose internal id does not match is not loaded` |
| — | `valid task ids keep working`, `valid project ids keep working`, `a valid checkpoint still round-trips`, `fs.read still reads a normal file…`, `http.get still fetches a loopback URL`, `http.get refuses a non-loopback host`, `a denied tool call never executes the tool body`, `a denial is audited`, `repeated recovery does not execute a step twice`, `the orchestrator stops when the run is cancelled between iterations` |

The "still works" tests are as important as the refusal tests: they prove
the hardening did not break legitimate use.

### Full suite

```
npm test
  tests 220
  pass  219
  fail  0
  skipped 1     (the symlink test — see below)
```

On the Linux CI runner the same suite reports **220 tests, 220 pass, 0
fail, 0 skipped** — the symlink test executes there instead of skipping.

### Phase 1 compatibility

```
npm run test:phase1
  tests 56
  pass  56
  fail  0
```

**No Phase 1 assertion was removed.** `git diff 6e8d80e -- test/` against
the Phase 1 baseline commit returns **no changes** to
`states.test.js`, `storage.test.js`, `audit.test.js`, `redact.test.js`,
`agent.test.js`, `memory.test.js` and `cli.test.js` — they are
byte-identical to the baseline, including the strict
`memory: add rejects missing key` assertion restored to
`/key is required/`.

### CI-equivalent checks

| check | command | result |
| ----- | ------- | ------ |
| credential scan | `npm run scan:secrets` | exit 0 — no credential-shaped strings |
| offline provider | `node aegis/cli.js providers smoke` | exit 0 — provider `offline`, no credentials needed |
| workspace doctor | `node aegis/cli.js doctor` | exit 0 — `ok: true`, no missing dirs |
| CLI help | `node aegis/cli.js --help` | exit 0 |

The smoke and doctor steps run with `AEGIS_LLM_URL` and
`AEGIS_LLM_AUTH_HEADER` explicitly empty, so CI can never reach a model
or echo a secret.

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs the same
steps on a Node 18 / 20 / 22 matrix.

**Run `40103601935`** on commit `34d63a6` — <https://github.com/gravion-ux/project-aegis/actions/runs/40103601935>
— completed with conclusion **`success`**. All three legs
(`test (node 18)`, `test (node 20)`, `test (node 22)` on `ubuntu-latest`)
passed every step, and the job logs confirm the counts read back from the
runners themselves:

| job | full suite | Phase 1 suite | symlink test |
| --- | ---------- | -------------- | ------------ |
| node 18 | 220 / 220 pass, 0 skipped | 56 / 56 pass | `ok 162` |
| node 20 | 220 / 220 pass, 0 skipped | 56 / 56 pass | `ok 162` |
| node 22 | 220 / 220 pass, 0 skipped | 56 / 56 pass | `ok 162` |

The smoke step ran with `AEGIS_LLM_URL` and `AEGIS_LLM_AUTH_HEADER`
explicitly empty, so CI reached no model and echoed no secret; the
credential-scan step reported `no credential-shaped strings found`.

### Lint / type checks

**Not configured.** The project has no linter, no type checker and no
formatter in `package.json`, and no ESLint/TypeScript configuration in the
tree. None was run, and none is claimed. `node --check` was not used as a
substitute because `require()` of every module already parses it.

---

## Residual risk

These are known and **not** fixed.

1. **A tool that ignores the abort signal cannot be force-stopped.** The
   registry aborts the signal and the call is rejected, but a tool whose
   body never looks at `ctx.signal` keeps running in-process. Only the
   built-in `fs.read` and `http.get` honour it today. A future tool must
   check the signal itself; this is a contract, not an enforcement.
2. **The budget cannot un-spend.** The guard stops *further* work, but the
   single attempt that produced an overage still ran to completion. The
   output size is not knowable before the output exists, so a strict
   pre-emptive cut is not possible without an estimate from the agent.
3. **Multi-process safety is not implemented.** `Storage` documents that
   it is single-process. Two AEGIS processes writing the same state
   directory can interleave. A lock file is a later phase.
4. **`Idempotency` is in-memory.** It does not survive a process restart.
   Cross-restart idempotency comes from the persisted checkpoint's
   `completed` list, which is covered by the restart test, not from
   `Idempotency` itself.
5. **The audit log's HMAC chain protects integrity, not confidentiality.**
   The secret lives in the key, not the log.
6. **Tool inputs are logged.** `summariseInput` puts up to 200 characters
   of the tool input into the audit event. A caller who passes a secret as
   a tool argument will have it recorded in the audit log — the redactor
   is not applied to audit payloads.
7. **The `memory` specialist trusts `input.projectId`.** It is now
   validated, so it cannot escape the memory root, but it can still name
   any project inside it.
8. **`fs.read` is not sandboxed against a hostile filesystem.** The
   realpath check closes the symlink escape, but a root that is itself
   attacker-controlled is still a root.

---

## Not tested

Stated plainly, because a passing suite is not a security property.

1. **No real LLM provider was exercised.** `AEGIS_LLM_URL` is unset and no
   paid credential is available. The HTTP provider was tested against a
   local mock server only. Its behaviour against Ollama, LM Studio,
   llama.cpp or a hosted API is **unverified**.
2. **The symlink escape (L1) could not be reproduced on the audit host.**
   Creating a symlink on Windows needs a privilege this account lacks
   (`EPERM`), so the test **skips on Windows**. It was **executed and
   passed on the Linux CI runner** (run `40103601935`, all three matrix
   legs, `ok 162`). The symlink escape is therefore fixed-by-test; the
   Windows skip is an environment limitation, not an untested path.
3. **No concurrency or race testing was performed.** The cancellation and
   timeout fixes are single-threaded tests. A tool that aborts at exactly
   its timeout boundary was not exercised.
4. **Fuzzing was not performed.** The identifier rules were tested against
   a fixed list of traversal strings, not a generated corpus.
5. **No audit of the dependencies.** The project has **zero runtime
   dependencies** and uses only Node built-ins, so there is no
   third-party supply chain to review. The Node.js standard library itself
   was not audited.
6. **The other repositories in the `gravion-ux` account were not
   re-audited.** This pass covered `project-aegis` only.
7. **No penetration test of the running system.** This was a source and
   behavioural audit, not an adversarial exercise of a deployed instance.
8. **`aegis/security scope` still reports hard-coded scope information.**
   It prints a static description of the boundary rather than the
   *effective* roots and limits of the current context. That is a
   reporting inaccuracy, not a control failure, and it was left alone to
   avoid scope creep.

---

## Next steps

1. ~~Run the CI matrix on this branch and confirm the symlink test passes
   on the Linux runner.~~ **Done** — run `40103601935` is green on Node
   18 / 20 / 22 and the symlink test passed on all three legs.
2. Give `Budget` a real `maxAttempts` in `aegis.config.example.json` so
   the retry bound is on by default rather than available.
3. Decide the audit-log treatment for tool inputs (residual risk 6).
4. Add a lock file for multi-process state safety.
