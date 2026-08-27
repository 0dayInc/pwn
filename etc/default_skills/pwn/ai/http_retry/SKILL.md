---
name: pwn-ai-httpretry
description: Drive PWN::AI::HttpRetry from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::HttpRetry
  source: pwn/ai/http_retry.rb
---

# PWN::AI::HttpRetry

Shared REST timeout / 429 / ReadTimeout policy for every AI provider. Default wall clock per attempt is 180s with up to 5 attempts (≈900s total). Short quiet sidecar hops stay single-shot.

## When to use

Call `PWN::AI::HttpRetry` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/http_retry.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::HttpRetry.help
PWN::AI::HttpRetry.timeout_s(opts)
```

## Public methods

- `timeout_s`
- `max_attempts`
- `retryable`
- `retry_after_s`
- `report_event`
- `authors`
- `help`
- `retryable?`

## Source

`pwn/ai/http_retry.rb`

## Verification

`PWN::AI::HttpRetry.respond_to?(:timeout_s)` after the
module is loaded. Read the source for parameter names.
