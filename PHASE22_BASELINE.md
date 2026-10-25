# Project AEGIS — Phase 2.2 Baseline Audit

**Repository:** <https://github.com/gravion-ux/project-aegis>
**Recorded:** 2026-10-25 (audit host, Asia/Kolkata)
**Audit branch:** `phase-2.2-reliability`, created from local `HEAD` `1f43f9e`
**Baseline commit audited:** `1f43f9ec69f7d2794898e5b614c57c083f327845`

**Purpose.** This document records the state of the repository *before* any
Phase 2.2 modification. It is the reference point for every Phase 2.2 finding:
if a behaviour changed between this baseline and the end of Phase 2.2, the
change is either a deliberate fix recorded in
[`PHASE22_SECURITY_AND_RELIABILITY_REPORT.md`](./PHASE22_SECURITY_AND_RELIABILITY_REPORT.md)
or a regression. Anything not listed there was already true at the baseline.

**Method.** The baseline was established by reading the tracked tree, by
running the project's own test and CI-equivalent commands, and by recording the
verified CI results of the Phase 2.1 push. No source file was modified before
these observations were captured.

---

## 1. Repository state at baseline

| property | value |
| -------- | ----- |
| remote | `origin` → `https://github.com/gravion-ux/project-aegis.git` |
| local branch at baseline | `main` |
| local `HEAD` | `1f43f9e` |
| `origin/main` (fetched) | `d8a81fb` |
| merge base with `origin/main` | **none** — the two histories are unrelated |
| content difference | **none** — `git diff --ignore-all-space --stat HEAD origin/main` is empty |
| tracked files | 53 |
| runtime dependencies | **0** |
| `package-lock.json` | absent |
| `node_modules/` | absent (nothing to install) |

### The unrelated-history situation

The local repository and the GitHub remote share **no merge base**. The local
history was rewritten (or re-created) at some point before this audit, so
`git merge origin/main` would refuse. This was already true at the Phase 2.1
baseline and is **not** a Phase 2.2 regression.

Because the two histories are unrelated, "is the remote up to date?" could not
be answered with `git log`. It was answered with a content diff instead:

```
git diff --ignore-all-space --stat HEAD origin/main
```

The result is **empty**, which means local `HEAD` and `origin/main` are
byte-equivalent apart from line endings. The two tips (`1f43f9e` and
`d8a81fb`) are the same two commits published under different hashes by the
GitHub App push path. Committing Phase 2.2 on top of the local `HEAD` and
publishing the changed files is therefore a faithful continuation of the
published tree, not a fork of it.

### Commit history (local `main`)

| commit | subject |
| ------ | ------- |
| `1f43f9e` | docs: record the verified Phase 2.1 CI result in the audit report |
| `ec72656` | Phase 2.1 Security Hardening Audit |
| `5aeb486` | Add issue templates, pull request template and a security policy |
| `9a75cc8` | docs: update README and DESIGN for Phase 0-2 |
| `3c6c051` | Merge Phase 2 into main |
| `eb86fea` | Phase 2: memory, providers, tools, budgets, specialists, orchestrator, recovery |
| `6e8d80e` | phase-1 baseline (38 tests pass) |

### Branches

| branch | note |
| ------ | ---- |
| `main` | local copy of the published tree |
| `phase-2` | Phase 2 feature branch, retained |
| `phase-2.2-reliability` | **created by this audit** from `1f43f9e` |
| `origin/main` | `d8a81fb` |

`phase-2.2-reliability` is named with a `phase-` prefix so that the existing CI
trigger glob `branches: ["main", "phase-*"]` matches it and the matrix runs on
push without editing the workflow's trigger.

---

## 2. Runtime and package information

| property | value |
| -------- | ----- |
| Node.js (audit host) | `v24.14.0` |
| npm (audit host) | `11.9.0` |
| declared engine range | `node >= 18.0.0` |
| CI matrix | Node 18, 20, 22 on `ubuntu-latest` |
| dependencies | none (`dependencies` and `devDependencies` are both absent) |
| module system | CommonJS (`require`) |
| test runner | built-in `node:test` (`node --test`) |
| linter / type checker | **not configured** — no ESLint, TypeScript or formatter config exists in the tree |

The project is deliberately zero-dependency: every module uses only Node
built-ins (`node:fs`, `node:path`, `node:http`, `node:crypto`, `node:test`).
There is therefore **no third-party supply chain to review**, but the Node
standard library itself remains outside the scope of this audit.

### `package.json` scripts at baseline

| script | command |
| ------ | ------- |
| `test` | `node --test` over 16 test files |
| `test:phase1` | `node --test` over the 8 Phase 1 test files |
| `test:phase2` | `node --test` over 9 Phase 2 test files |
| `test:security` | `node --test test/security-hardening.test.js` |
| `smoke` | `node aegis/cli.js providers smoke` |
| `scan:secrets` | `node scripts/scan-secrets.js` |
| `demo` | `node aegis/cli.js doctor` |

Phase 2.2 added `test:adversarial` and `test:phase22`, and added the two new
test files to `test` and `test:phase2`. `test:phase1` was **not** modified —
the Phase 1 compatibility surface is exactly what it was at the baseline.

---

## 3. Source inventory (trust-boundary map)

All source is under `aegis/`. Line counts are at the baseline commit.

| file | lines | trust boundary it owns |
| ---- | ----- | ----------------------- |
| `aegis/paths.js` | 105 | identifier validation, root containment (Phase 2.1) |
| `aegis/storage.js` | 153 | task persistence, task index, id → filename mapping |
| `aegis/recovery.js` | 163 | checkpoint write/load/clear, interrupted-run detection |
| `aegis/memory.js` | 297 | persistent memory store, context assembly, project scoping |
| `aegis/usage.js` | 254 | global and per-task budgets, ceilings, preflight |
| `aegis/tools/registry.js` | 465 | default-deny tool registry, allowlists, risk ceiling, `fs.read`, `http.get` |
| `aegis/providers/http.js` | 233 | outbound HTTP, timeouts, response parsing, usage extraction |
| `aegis/providers/base.js` | 38 | provider error contract |
| `aegis/providers/registry.js` | 80 | provider selection |
| `aegis/providers/offline.js` | 66 | offline provider |
| `aegis/orchestrator.js` | 373 | agent loop, retries, output validation, budget gate |
| `aegis/audit.js` | 138 | append-only audit log, HMAC chain |
| `aegis/redact.js` | 90 | secret redaction |
| `aegis/agent.js` | 106 | agent execution contract |
| `aegis/specialists.js` | 187 | built-in agent roles |
| `aegis/router.js` | 258 | CLI command routing |
| `aegis/cli.js` | 75 | CLI entry point |
| `aegis/task.js` | 94 | task model and state machine |
| `aegis/states.js` | 46 | task state machine |
| `aegis/config.js` | 104 | configuration loading |
| `aegis/log.js` | 51 | logging |
| `aegis/index.js` | 119 | public exports |
| `scripts/scan-secrets.js` | 116 | credential-shaped string scanner |

---

## 4. Baseline test and CI results

All commands below were run on the audit host against the **unmodified** tree
at `1f43f9e`.

### 4.1 Full suite — `npm test`

```
tests   220
pass    219
fail      0
skipped   1
```

The single skip is the Phase 2.1 symlink-escape test
(`fs.read refuses to follow a symlink out of the allowed root`). Creating a
symlink on this Windows host requires a privilege the account does not have
(`EPERM`), so the test skips locally and is exercised on the Linux CI runner.

### 4.2 Phase 1 compatibility — `npm run test:phase1`

```
tests   56
pass    56
fail     0
skipped  0
```

### 4.3 CI-equivalent checks

| check | command | result |
| ----- | ------- | ------ |
| credential scan | `npm run scan:secrets` | exit 0 — `no credential-shaped strings found` |
| offline provider | `npm run smoke` | exit 0 — provider `offline`, `ok: true` |
| workspace doctor | `node aegis/cli.js doctor` | exit 0 — `ok: true`, `missing: []` |
| CLI help | `node aegis/cli.js --help` | exit 0 |

> Note on reading exit codes in PowerShell: piping a command into
> `Select-Object -First N` terminates the pipeline early and makes Node exit
> with a broken-pipe code (`-1`). That is a shell artefact, not a CLI failure.
> The `--help` exit code above was measured as `node aegis/cli.js --help |
> Out-Null; $LASTEXITCODE` → `0`.

### 4.4 CI configuration (`.github/workflows/ci.yml`)

| property | value |
| -------- | ----- |
| triggers | `push` to `main` and `phase-*`; `pull_request` to `main` |
| permissions | `contents: read` |
| runner | `ubuntu-latest` |
| matrix | Node 18 / 20 / 22, `fail-fast: false` |
| steps | checkout → setup-node → print version → install → **full suite** → **Phase 1 suite** → **offline provider smoke** → **CLI doctor** → **credential scan** |

The smoke step runs with `AEGIS_LLM_URL` and `AEGIS_LLM_AUTH_HEADER`
explicitly set to empty, so CI can never reach a model endpoint or echo a
credential. The install step is a no-op in practice — there is no
`package-lock.json` and no dependencies.

### 4.5 Verified CI runs at the baseline

Both Phase 2.1 runs completed with conclusion `success`:

| run | commit | conclusion | matrix result |
| --- | ------ | ---------- | ------------- |
| [40103601935](https://github.com/gravion-ux/project-aegis/actions/runs/40103601935) | `34d63a6` | `success` | Node 18/20/22 — 220/220 pass, 0 skipped; symlink test `ok 162` on all three legs |
| [40104409191](https://github.com/gravion-ux/project-aegis/actions/runs/40104409191) | `d8a81fb` | `success` | Node 18/20/22 — 220/220 pass, 0 skipped; symlink test `ok 162` on all three legs |

---

## 5. Phase 2.1 findings → source and test map

Phase 2.1 fixed 14 findings. This map is the baseline that Phase 2.2 audited
against — each row was re-read and re-tested during Phase 2.2. The
"Phase 2.2 status" column is the outcome of that re-audit.

| Phase 2.1 finding | source | regression test | Phase 2.2 status |
| ----------------- | ------ | --------------- | --------------- |
| **H1** path traversal via task id | `aegis/storage.js` (`get`/`put`/`remove`) | `test/security-hardening.test.js` — `Storage.put refuses a traversing task id…`, `Storage.get refuses…`, `Storage.remove refuses…` | still closed; **strengthened** (P22-01…P22-05) |
| **H2** path traversal via checkpoint task id | `aegis/recovery.js` (`CheckpointStore._file`) | `…save refuses…`, `…load refuses…`, `…clear refuses…` | still closed; **strengthened** (P22-07…P22-09) |
| **H3** path traversal via memory project id | `aegis/memory.js` (`_file`, `_checkpointFile`) | `Memory.add refuses a traversing project id`, `Memory checkpoint refuses…` | still closed; **strengthened** (P22-10, P22-11) |
| **M1** refused budget call still charged the budget | `aegis/usage.js` (`Budget.record`) | `a refused Budget.record leaves the counters untouched`, `the budget error reports the unchanged totals` | **partially reopened** — the `attempts` ceiling was not preflighted (P22-06) |
| **M2** `BudgetManager` preflight used the wrong argument keys | `aegis/usage.js` (`BudgetManager.record`) | `the global budget preflight fires before the usage is recorded` | still closed; extended to the per-task budget (P22-06) |
| **M3** per-task budget limits silently ignored | `aegis/usage.js` (`BudgetManager.forTask`) | `per-task limits set after the first record are applied` | still closed |
| **M4** orchestrator had no budget gate | `aegis/orchestrator.js` | `the orchestrator refuses to start when the budget is exhausted` | still closed; **strengthened** (P22-23) |
| **M5** retries never charged to the budget | `aegis/orchestrator.js` | `every attempt is charged to the budget`, `a retry loop is charged… and can be bounded by the budget` | still closed; the refusal atomicity was incomplete (P22-06) |
| **M6** tool registry ignored the abort signal | `aegis/tools/registry.js` (`ToolRegistry.run`) | `a cancelled run does not start the tool` | still closed |
| **M7** timed-out tool kept running | `aegis/tools/registry.js` (`_withTimeout`) | `a timeout aborts the tool instead of abandoning it`, `an external cancellation reaches a running tool` | still closed — but only the *built-in* tools honour the signal (see residual risk) |
| **M8** `fs.read` / `http.get` loaded unbounded data | `aegis/tools/registry.js` | `fs.read refuses a file over the size limit`, `http.get refuses a response over the size limit` | still closed; `fs.read` had a **TOCTOU hole** (P22-16) |
| **M9** CLI died fatally on a missing task | `aegis/router.js` | `the CLI reports a missing task as a usage error, not a crash` | still closed |
| **L1** `fs.read` followed a symlink out of an allowed root | `aegis/tools/registry.js` | `fs.read refuses to follow a symlink out of the allowed root` (**skips on Windows, passes on Linux CI**) | still closed |
| **L2** HTTP provider buffered an unbounded response | `aegis/providers/http.js` | `the HTTP provider refuses an oversized response` | still closed |
| **L3** provider error message could echo a secret | `aegis/providers/http.js` | `an error body that echoes a token is redacted` | still closed; the redactor itself was too narrow (P22-25) |
| **L4** checkpoint could be adopted under another task's name | `aegis/recovery.js` (`CheckpointStore.load`) | `a checkpoint whose internal id does not match is not loaded` | still closed |

**Summary:** 12 of the 14 Phase 2.1 fixes were fully intact at the baseline.
Two were partially reopened by Phase 2.2 probes — **M1/M5** (budget refusal
was not atomic for the `attempts` ceiling) and **M8/L1** (`fs.read` had a
time-of-check/time-of-use gap between the size check and the read). The
Phase 2.1 *report* also listed several gaps that were never fixed; those
became Phase 2.2 findings (see §6).

---

## 6. Inherited risk carried into Phase 2.2

Phase 2.1 ended with an explicit residual-risk list and a "not tested" list.
Both were treated as Phase 2.2 input, not as accepted risk.

### 6.1 Phase 2.1 residual risks

| # | Phase 2.1 residual risk | Phase 2.2 outcome |
| - | ----------------------- | ----------------- |
| 1 | a tool that ignores the abort signal cannot be force-stopped | **not fixed** — carried forward; it is a contract, not an enforcement |
| 2 | the budget cannot un-spend the attempt that caused the overage | **not fixed** — inherent; carried forward |
| 3 | multi-process safety is not implemented (no lock file) | **partially fixed** — the storage index no longer overwrites a concurrent writer's entries (P22-29); a lock file is still absent, so a truly simultaneous write can still race |
| 4 | `Idempotency` is in-memory and does not survive a restart | **not fixed** — carried forward |
| 5 | the audit HMAC chain protects integrity, not confidentiality | **not fixed** — carried forward, but see below |
| 6 | tool inputs are logged unredacted into the audit event | **fixed** — P22-26 |
| 7 | the `memory` specialist can still name any project inside the memory root | **not fixed** — carried forward |
| 8 | `fs.read` is not sandboxed against a hostile filesystem root | **partially fixed** — the TOCTOU gap is closed (P22-16); a hostile *root* remains open |

Phase 2.1 residual risk 5 also concealed a stronger problem found in Phase 2.2:
the audit chain's HMAC key was the **published constant**
`aegis-default-audit-key`, so the chain was integrity-*shaped* but not
integrity-*enforced* against anyone who had read the repository
(P22-27, P22-28).

### 6.2 Phase 2.1 "not tested" list

| # | Phase 2.1 gap | Phase 2.2 outcome |
| - | ------------- | ----------------- |
| 1 | no real LLM provider exercised | **still not tested** — no credential or endpoint is available; the HTTP provider was tested against a local mock server only |
| 2 | symlink escape not reproducible on Windows | **unchanged** — still verified only on the Linux CI runner |
| 3 | no concurrency or race testing | **addressed, with a caveat** — workstream 2.2C added 10 concurrency tests and **found a real defect** (P22-29: a second writer silently erased the first writer's indexed tasks). The caveat: no true multi-*process* test was run, so 2.2C is reported PARTIAL |
| 4 | no fuzzing performed | **addressed** — `test/adversarial.test.js`, a seeded, deterministic, offline harness |
| 5 | no dependency audit (there are no dependencies) | **unchanged** — zero runtime dependencies confirmed; the Node standard library was still not audited |
| 6 | other repositories in the account not re-audited | **unchanged** — out of scope; this pass covered `project-aegis` only |
| 7 | no penetration test of a deployed instance | **unchanged** — this is a source-and-behaviour audit |
| 8 | `aegis security scope` reports static scope information | **not fixed** — reporting inaccuracy, left alone to avoid scope creep |

---

## 7. Baseline conclusion

The tree at `1f43f9e` was in a clean, green state: the full suite passed,
the Phase 1 compatibility suite passed unchanged, every CI-equivalent command
exited 0, and both published CI runs were green on Node 18/20/22.

That green state is precisely what made Phase 2.2 worthwhile. Every one of the
29 defects recorded in the Phase 2.2 report was live **while the baseline
suite was passing** — the suite simply never exercised the path. The
"not tested" items in §6.2 are the reason: the gaps were in areas the suite
did not cover, not in areas it covered badly.
