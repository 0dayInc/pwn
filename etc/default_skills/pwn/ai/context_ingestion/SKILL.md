---
name: pwn-ai-context
description: Drive PWN::AI::Context from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Context
  source: pwn/ai/context_ingestion.rb
---

# PWN::AI::Context

Local evidence ingestion; XML is bounded to 100 element levels before XPath. Unavailable embeddings never become synthetic vectors.

## When to use

Call `PWN::AI::Context` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/context_ingestion.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Context.help
PWN::AI::Context.ingest(opts)
```

## Public methods

- `authors`
- `ingest`
- `retrieve`
- `help`
- `attach_disasm`
- `attach_file`
- `attach_hexdump`
- `attach_http_transcript`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/context_ingestion.rb`

## Verification

`PWN::AI::Context.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
