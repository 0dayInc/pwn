---
name: pwn-ai-anthropic
description: Drive PWN::AI::Anthropic from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Anthropic
  source: pwn/ai/anthropic.rb
---

# PWN::AI::Anthropic

This plugin interacts with Anthropic's Claude API. It provides methods to list models, generate completions, and chat. API documentation: https://docs.anthropic.com/en/api Obtain an API key from https://console.anthropic.com/

## When to use

Call `PWN::AI::Anthropic` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/anthropic.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Anthropic.help
PWN::AI::Anthropic.refresh_oauth_bearer_token(opts)
```

## Public methods

- `refresh_oauth_bearer_token`
- `obtain_oauth_bearer_token`
- `get_models`
- `chat_with_tools`
- `chat`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/anthropic.rb`

## Verification

`PWN::AI::Anthropic.respond_to?(:refresh_oauth_bearer_token)` after the
module is loaded. Read the source for parameter names.
