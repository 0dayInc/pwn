---
name: pwn-plugins-jobs
description: Drive PWN::Plugins::Jobs from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Jobs
  source: pwn/plugins/jobs.rb
---

# PWN::Plugins::Jobs

Background jobs that survive a pwn-ai turn (scans, fuzz campaigns).

## When to use

Call `PWN::Plugins::Jobs` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/jobs.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Jobs.help
PWN::Plugins::Jobs.required_bins(opts)
```

## Public methods

- `required_bins`
- `start`
- `watch`
- `status`
- `tail`
- `result`
- `harvest`
- `list`
- `stop`
- `authors`
- `help`

## Source

`pwn/plugins/jobs.rb`

## Verification

`PWN::Plugins::Jobs.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
