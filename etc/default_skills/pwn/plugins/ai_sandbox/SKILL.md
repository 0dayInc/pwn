---
name: pwn-plugins-aisandbox
description: Drive PWN::Plugins::AISandbox from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::AISandbox
  source: pwn/plugins/ai_sandbox.rb
---

# PWN::Plugins::AISandbox

Forked worker for model-authored shell/Ruby with Landlock/seccomp profiles.

## When to use

Call `PWN::Plugins::AISandbox` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/ai_sandbox.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::AISandbox.help
PWN::Plugins::AISandbox.required_bins(opts)
```

## Public methods

- `required_bins`
- `mode`
- `classify`
- `exec`
- `wrap_shell`
- `wrap_ruby`
- `authors`
- `help`

## Source

`pwn/plugins/ai_sandbox.rb`

## Verification

`PWN::Plugins::AISandbox.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
