---
name: pwn-sast-tasktag
description: Drive PWN::SAST::TaskTag from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::TaskTag
  source: pwn/sast/task_tag.rb
---

# PWN::SAST::TaskTag

SAST Module used to identify task tags such as TODO, SECURITY, FIXME, etc to ensure developers aren't introducing security-related bugs into source code.

## When to use

Call `PWN::SAST::TaskTag` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/task_tag.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::TaskTag.help
PWN::SAST::TaskTag.scan(opts)
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

`pwn/sast/task_tag.rb`

## Verification

`PWN::SAST::TaskTag.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
