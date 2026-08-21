---
name: pwn-sast-cmdexecutionscala
description: Drive PWN::SAST::CmdExecutionScala from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::CmdExecutionScala
  source: pwn/sast/cmd_execution_scala.rb
---

# PWN::SAST::CmdExecutionScala

SAST Module used to identify command execution residing within scala source code.

## When to use

Call `PWN::SAST::CmdExecutionScala` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/cmd_execution_scala.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::CmdExecutionScala.help
PWN::SAST::CmdExecutionScala.scan(opts)
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

`pwn/sast/cmd_execution_scala.rb`

## Verification

`PWN::SAST::CmdExecutionScala.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
