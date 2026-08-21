---
name: pwn-bounty-lifecycleauthzreplay
description: Drive PWN::Bounty::LifecycleAuthzReplay from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Bounty::LifecycleAuthzReplay
  source: pwn/bounty/lifecycle_authz_replay.rb
---

# PWN::Bounty::LifecycleAuthzReplay

YAML-driven helper for capturing lifecycle authz evidence across pre/post state transitions (e.g., collaborator removal, role change, project visibility flips) with report-ready artifacts.

## When to use

Call `PWN::Bounty::LifecycleAuthzReplay` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/bounty/lifecycle_authz_replay.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Bounty::LifecycleAuthzReplay.help
PWN::Bounty::LifecycleAuthzReplay.load_plan(opts)
```

## Public methods

- `load_plan`
- `start_run`
- `record_observation`
- `finalize_run`
- `normalize_plan`
- `authors`
- `help`

## Source

`pwn/bounty/lifecycle_authz_replay.rb`

## Verification

`PWN::Bounty::LifecycleAuthzReplay.respond_to?(:load_plan)` after the
module is loaded. Read the source for parameter names.
