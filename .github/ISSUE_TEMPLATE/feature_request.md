name: Feature or change
description: Suggest a change to the design, a new agent, or a new tool
labels: ["enhancement"]
body:
  - type: markdown
    attributes:
      value: |
        Design discussion is welcome. Please describe the *boundary* you want
        to change — this project treats permissions, limits and auditability
        as part of the feature, not as an afterthought.

  - type: textarea
    id: what
    attributes:
      label: What would change
      description: The behaviour, in one or two sentences.
    validations:
      required: true

  - type: dropdown
    id: layer
    attributes:
      label: Which layer
      options:
        - Tool registry (new tool, permission, risk level)
        - Providers (a new model adapter or routing rule)
        - Agents / manifest (a new specialist or its declaration)
        - Memory (schema, retrieval, retention)
        - Orchestrator (limits, delegation, cancellation)
        - CLI or docs
    validations:
      required: true

  - type: textarea
    id: boundaries
    attributes:
      label: Safety boundary
      description: |
        What should this new capability be *unable* to do? A default-deny
        rule, a scope file, an allowlist, a risk ceiling?

  - type: textarea
    id: tests
    attributes:
      label: How it would be tested
      description: The test you would want to see. Offline and deterministic is preferred.
