---
name: pwn-sast-cmdexecutionruby
description: Drive PWN::SAST::CmdExecutionRuby from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::CmdExecutionRuby
  source: pwn/sast/cmd_execution_ruby.rb
---

# PWN::SAST::CmdExecutionRuby

SAST Module used to identify command execution residing within Ruby source code.

## When to use

Call `PWN::SAST::CmdExecutionRuby` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/cmd_execution_ruby.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::CmdExecutionRuby.help
PWN::SAST::CmdExecutionRuby.scan(opts)
```

## Public methods

- `scan`
- `security_references`
- `authors`
- `help`

## References

- `references/security.md` — CWE / NIST mapping
- `references/urls.md` — URLs from source

## Source

`pwn/sast/cmd_execution_ruby.rb`

## Verification

`PWN::SAST::CmdExecutionRuby.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
