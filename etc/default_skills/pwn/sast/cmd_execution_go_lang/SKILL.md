---
name: pwn-sast-cmdexecutiongolang
description: Drive PWN::SAST::CmdExecutionGoLang from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::CmdExecutionGoLang
  source: pwn/sast/cmd_execution_go_lang.rb
---

# PWN::SAST::CmdExecutionGoLang

SAST Module used to identify command execution residing within GoLang source code.

## When to use

Call `PWN::SAST::CmdExecutionGoLang` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/cmd_execution_go_lang.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::CmdExecutionGoLang.help
PWN::SAST::CmdExecutionGoLang.scan(opts)
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

`pwn/sast/cmd_execution_go_lang.rb`

## Verification

`PWN::SAST::CmdExecutionGoLang.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
