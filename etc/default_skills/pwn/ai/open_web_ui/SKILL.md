---
name: pwn-ai-openwebui
description: Drive PWN::AI::OpenWebUI from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::OpenWebUI
  source: pwn/ai/open_web_ui.rb
---

# PWN::AI::OpenWebUI

Client for Open WebUI's REST API via PWN::Plugins::TransparentBrowser (:rest). Live Open WebUI routes (gateway base_uri, no trailing slash): GET /api/v1/models OpenAI-compat model list (:data) POST /api/v1/chat/completions OpenAI-compat chat (SSE when stream:true) POST /api/chat/completions alias of the above GET /ollama/api/tags proxied Ollama tags (:models) POST /ollama/api/chat proxied Ollama chat (NDJSON when stream:true) POST /ollama/api/embed proxied embeddings (see PWN::MemoryIndex) Bare /api/chat and bare /v1/* are NOT API routes on stock Open WebUI — they 405 or return the SPA HTML shell.

## When to use

Call `PWN::AI::OpenWebUI` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/open_web_ui.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::OpenWebUI.help
PWN::AI::OpenWebUI.get_models(opts)
```

## Public methods

- `get_models`
- `chat_with_tools`
- `chat`
- `authors`
- `help`

## Source

`pwn/ai/open_web_ui.rb`

## Verification

`PWN::AI::OpenWebUI.respond_to?(:get_models)` after the
module is loaded. Read the source for parameter names.
