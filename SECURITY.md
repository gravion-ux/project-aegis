# Security Policy

Project AEGIS is a security tool, so it is reasonable to expect that its
own security gets treated seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Use GitHub's
private vulnerability reporting on this repository
(<https://github.com/gravion-ux/project-aegis/security/advisories/new>),
or open a private issue if that is not available to you.

Include:

- what the issue is, in one or two sentences
- the version or commit SHA it affects
- the smallest reproduction you have — a failing test is ideal
- the impact you believe it has

You can expect an acknowledgement within a few days. Fix and disclosure
timing can be agreed before anything is public.

## Scope

This repository is a **toolkit**, not a service. Reports about the
tooling itself are in scope: the CLI, the memory store, the provider
adapter, the tool registry, the orchestrator, and the recovery path.

Reports about a third-party system that this tool was pointed at are out of
scope for this repository — those go to the owner of that system.

## Design assumptions

These are deliberate, and a report that shows one of them is broken is
very welcome:

- **Tools are default-deny.** An unregistered tool cannot run. A task can
  only call a tool on its own `allowedTools` list, and only up to its
  declared risk ceiling.
- **No unrestricted shell.** There is no shell tool in the registry.
- **The filesystem tool is rooted.** `fs.read` refuses paths outside an
  explicit `allowedRoots` list.
- **The HTTP tool is loopback-only.** `http.get` rejects any non-loopback
  host.
- **Paid providers are opt-in.** The router raises an error rather than
  silently substituting a different provider.
- **Credentials never enter the repository.** Provider endpoints come from
  the environment, `aegis.config.json` is gitignored, and
  `scripts/scan-secrets.js` runs in CI over the tracked tree.
- **Audit logs are append-only** and HMAC-chained.
- **Memory is redacted before write.**

## Supported versions

Only the current `main` branch is supported. Older commits are kept for
history, not for backports.
