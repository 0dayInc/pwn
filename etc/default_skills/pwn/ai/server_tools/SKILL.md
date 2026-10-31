---
name: pwn-ai-servertools
description: Use provider-hosted tools without replacing Registry client tools.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::ServerTools
  source: pwn/ai/server_tools.rb
---

# PWN::AI::ServerTools

Open WebUI is the only engine with a user-installed tool workspace. Ask Jev
runs there through `workspace_tool` or `chat(server_tools:)`. Do not send a
client `tools` array on that same Open WebUI request.

Anthropic, Gemini, and OpenAI Responses can carry their fixed hosted tools
beside Registry tools. xAI hosted tools use the Responses API, not
chat/completions. Ollama has no server-side tool workspace.

## Source

`pwn/ai/server_tools.rb`
