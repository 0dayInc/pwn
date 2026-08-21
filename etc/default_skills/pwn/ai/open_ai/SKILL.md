---
name: pwn-ai-openai
description: Drive PWN::AI::OpenAI from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::OpenAI
  source: pwn/ai/open_ai.rb
---

# PWN::AI::OpenAI

This plugin is used for interacting w/ OpenAI's REST API using the 'rest' browser type of PWN::Plugins::TransparentBrowser. This is based on the following OpenAI API Specification: https://api.openai.com/v1

## When to use

Call `PWN::AI::OpenAI` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/open_ai.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::OpenAI.help
PWN::AI::OpenAI.refresh_oauth_bearer_token(opts)
```

## Public methods

- `refresh_oauth_bearer_token`
- `obtain_oauth_bearer_token`
- `get_models`
- `chat_with_tools`
- `chat`
- `img_gen`
- `vision`
- `create_fine_tune`
- `list_fine_tunes`
- `get_fine_tune_status`
- `cancel_fine_tune`
- `get_fine_tune_events`
- `delete_fine_tune_model`
- `list_files`
- `upload_file`
- `delete_file`
- `get_file`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/open_ai.rb`

## Verification

`PWN::AI::OpenAI.respond_to?(:refresh_oauth_bearer_token)` after the
module is loaded. Read the source for parameter names.
