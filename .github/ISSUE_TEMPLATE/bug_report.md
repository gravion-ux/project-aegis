name: Bug report
description: Something in the tool behaves in a way you did not expect
labels: ["bug"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for the report. Please keep it reproducible — a failing test
        or a command with its output is worth more than a description.

  - type: input
    id: version
    attributes:
      label: Version or commit
      description: The commit SHA, or `git log -1`.
      placeholder: "e.g. 9a75cc8"
    validations:
      required: true

  - type: dropdown
    id: area
    attributes:
      label: Area
      options:
        - Task lifecycle / state machine
        - Memory
        - Provider routing
        - Tool registry / permissions
        - Budget or resource limits
        - Orchestrator / specialist agents
        - Cancellation / checkpoint / resume
        - CLI
        - CI or documentation
    validations:
      required: true

  - type: textarea
    id: repro
    attributes:
      label: Steps to reproduce
      description: Commands, inputs, and what you expected instead.
      render: shell
    validations:
      required: true

  - type: textarea
    id: logs
    attributes:
      label: Output
      description: Paste the console output. Please redact any credential first.
      render: shell

  - type: input
    id: env
    attributes:
      label: Node version and OS
      placeholder: "Node v20.11.0, Windows 11"
