---
name: pwn-sast-cmdexecutionpython
description: Drive PWN::SAST::CmdExecutionPython from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::CmdExecutionPython
  source: pwn/sast/cmd_execution_python.rb
---

# PWN::SAST::CmdExecutionPython

SAST Module used to identify command execution residing within Python source code.

## When to use

Call `PWN::SAST::CmdExecutionPython` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/cmd_execution_python.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::CmdExecutionPython.help
PWN::SAST::CmdExecutionPython.scan(opts)
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

`pwn/sast/cmd_execution_python.rb`

## Verification

`PWN::SAST::CmdExecutionPython.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
