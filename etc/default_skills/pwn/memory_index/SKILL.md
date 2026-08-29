---
name: pwn-memoryindex
description: Drive PWN::MemoryIndex from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::MemoryIndex
  source: pwn/memory_index.rb
---

# PWN::MemoryIndex

PWN::MemoryIndex is a lightweight local embedding index over PWN::Memory (~/.pwn/memory.json) so PromptBuilder can inject the N MOST-RELEVANT memories for the current request instead of the N newest. Embeddings prefer a direct Ollama /api/embed endpoint (PWN::Env[:ai][:ollama][:embed_model], default 'nomic-embed-text'). When only Open WebUI is configured, embeddings go through its /ollama/api/embed proxy with the openwebui key/base_uri. Index layout (~/.pwn/memory.idx): { "<key>": { "sha": "<sha16 of value>", "vec": [Float,…] }, … } Rebuilds are incremental: only entries whose value-sha changed are (re)embedded, so a warm index costs one embed call (the query).

## When to use

Call `PWN::MemoryIndex` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/memory_index.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::MemoryIndex.help
PWN::MemoryIndex.available(opts)
```

## Public methods

- `available`
- `recall_semantic`
- `to_context`
- `refresh`
- `embed`
- `reset`
- `authors`
- `help`
- `available?`

## Source

`pwn/memory_index.rb`

## Verification

`PWN::MemoryIndex.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
