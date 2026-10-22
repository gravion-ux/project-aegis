## What this changes

<!-- One or two sentences. What is different after this pull request? -->

## Why

<!-- Link the issue it closes, or state the problem it solves. -->

## Safety boundary

<!-- If this adds or widens a capability, say what it still cannot do:
     which tool it may call, what it is scoped to, what it refuses.
     A capability with no stated boundary is not ready to merge. -->

## How it was verified

<!-- The exact command you ran, and what it printed.
     `npm test` is expected to be green and the count must go up, not down. -->

## Checklist

- [ ] `npm test` passes locally
- [ ] `npm run scan:secrets` reports nothing
- [ ] No credential, token, or real endpoint appears anywhere in the diff
- [ ] New behaviour has a test, including the case it refuses
- [ ] Public docs (`README.md`, `docs/DESIGN.md`) match the code
