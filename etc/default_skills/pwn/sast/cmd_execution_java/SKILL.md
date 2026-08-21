---
name: pwn-sast-cmdexecutionjava
description: Drive PWN::SAST::CmdExecutionJava from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::CmdExecutionJava
  source: pwn/sast/cmd_execution_java.rb
---

# PWN::SAST::CmdExecutionJava

SAST Module used to identify command execution residing within Java source code.

## When to use

Call `PWN::SAST::CmdExecutionJava` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/cmd_execution_java.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::CmdExecutionJava.help
PWN::SAST::CmdExecutionJava.scan(opts)
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

`pwn/sast/cmd_execution_java.rb`

## Verification

`PWN::SAST::CmdExecutionJava.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
