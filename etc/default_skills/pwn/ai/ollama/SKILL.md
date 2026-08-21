---
name: pwn-ai-ollama
description: Drive PWN::AI::Ollama from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Ollama
  source: pwn/ai/ollama.rb
---

# PWN::AI::Ollama

Direct client for a local/remote Ollama server REST API. No API key is required for a stock ollama serve (http://127.0.0.1:11434). Paths are native Ollama: GET /api/tags POST /api/chat (native tool_calls, options.num_ctx / num_predict) POST /api/embed POST /v1/chat/completions (OpenAI-compat shim) Spec: https://github.com/ollama/ollama/blob/main/docs/api.md

## When to use

Call `PWN::AI::Ollama` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/ollama.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Ollama.help
PWN::AI::Ollama.get_models(opts)
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

`pwn/ai/ollama.rb`

## Verification

`PWN::AI::Ollama.respond_to?(:get_models)` after the
module is loaded. Read the source for parameter names.
