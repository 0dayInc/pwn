---
name: pwn-ai-sandbox
description: Drive PWN::AI::Sandbox from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Sandbox
  source: pwn/ai/sandbox.rb
---

# PWN::AI::Sandbox

Forked worker for model-authored shell/Ruby with Landlock/seccomp profiles.

## When to use

Call `PWN::AI::Sandbox` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/sandbox.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Sandbox.help
PWN::AI::Sandbox.required_bins(opts)
```

## Public methods

- `required_bins`
- `mode`
- `classify`
- `exec`
- `wrap_shell`
- `wrap_ruby`
- `control_directory`
- `protect_call`
- `swarm_control`
- `workspace`
- `task_directory`
- `prepare_write_roots`
- `protected_roots`
- `authors`
- `help`

## Source

`pwn/ai/sandbox.rb`

## Verification

`PWN::AI::Sandbox.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
