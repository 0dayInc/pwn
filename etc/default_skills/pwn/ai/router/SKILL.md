---
name: pwn-ai-router
description: Drive PWN::AI::Router from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Router
  source: pwn/ai/router.rb
---

# PWN::AI::Router

Task-class model routing from pwn.yaml ai_router / model_routes.

## When to use

Call `PWN::AI::Router` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/router.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Router.help
PWN::AI::Router.required_bins(opts)
```

## Public methods

- `required_bins`
- `resolve`
- `summarize`
- `usage`
- `reset_usage`
- `authors`
- `help`

## Source

`pwn/ai/router.rb`

## Verification

`PWN::AI::Router.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
