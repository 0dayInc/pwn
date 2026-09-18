---
name: pwn-engagement
description: Drive PWN::Engagement from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Engagement
  source: pwn/engagement.rb
---

# PWN::Engagement

Engagement scope, host state, and vault refs under ~/.pwn/engagements.

## When to use

Call `PWN::Engagement` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/engagement.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Engagement.help
PWN::Engagement.open(opts)
```

## Public methods

- `open`
- `close`
- `status`
- `in_scope`
- `warn_unless_in_scope`
- `record_host`
- `hosts`
- `merge_scan`
- `record_scan`
- `scans`
- `authors`
- `help`
- `in_scope?`

## Source

`pwn/engagement.rb`

## Verification

`PWN::Engagement.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
