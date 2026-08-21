---
name: pwn-ai-gemini
description: Drive PWN::AI::Gemini from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Gemini
  source: pwn/ai/gemini.rb
---

# PWN::AI::Gemini

This plugin interacts with Google's Gemini API (Generative Language). It provides methods to list models, generate completions, and chat, plus a native tool-calling adapter (`chat_with_tools`) for PWN::AI::Agent::Loop. API documentation: https://ai.google.dev/api Obtain an API key from https://aistudio.google.com/app/apikey

## When to use

Call `PWN::AI::Gemini` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/gemini.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Gemini.help
PWN::AI::Gemini.get_models(opts)
```

## Public methods

- `get_models`
- `chat_with_tools`
- `chat`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/gemini.rb`

## Verification

`PWN::AI::Gemini.respond_to?(:get_models)` after the
module is loaded. Read the source for parameter names.
