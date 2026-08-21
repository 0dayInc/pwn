---
name: pwn-sast-testcaseengine
description: Drive PWN::SAST::TestCaseEngine from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::TestCaseEngine
  source: pwn/sast/test_case_engine.rb
---

# PWN::SAST::TestCaseEngine

SAST Module used to execute PWN::SAST::* modules

## When to use

Call `PWN::SAST::TestCaseEngine` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/test_case_engine.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::TestCaseEngine.help
PWN::SAST::TestCaseEngine.execute(opts)
```

## Public methods

- `execute`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/sast/test_case_engine.rb`

## Verification

`PWN::SAST::TestCaseEngine.respond_to?(:execute)` after the
module is loaded. Read the source for parameter names.
