---
name: pwn-reports-engagement
description: Drive PWN::Reports::Engagement from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::Engagement
  source: pwn/reports/engagement.rb
---

# PWN::Reports::Engagement

Compile engagement findings into a client-ready HTML/Markdown report.

## When to use

Call `PWN::Reports::Engagement` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/engagement.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::Engagement.help
PWN::Reports::Engagement.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## Source

`pwn/reports/engagement.rb`

## Verification

`PWN::Reports::Engagement.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
