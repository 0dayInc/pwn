---
name: pwn-ai-grok
description: Drive PWN::AI::Grok from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Grok
  source: pwn/ai/grok.rb
---

# PWN::AI::Grok

This plugin interacts with xAI's Grok API, similar to the Grok plugin. It provides methods to list models, generate completions, and chat. API documentation: https://docs.x.ai/docs Obtain an API key from https://x.ai/api

## When to use

Call `PWN::AI::Grok` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/grok.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Grok.help
PWN::AI::Grok.refresh_oauth_bearer_token(opts)
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

`pwn/ai/grok.rb`

## Verification

`PWN::AI::Grok.respond_to?(:refresh_oauth_bearer_token)` after the
module is loaded. Read the source for parameter names.
