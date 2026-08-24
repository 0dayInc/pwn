---
name: pwn-ai-redteam-vectorandembeddingweaknesses
description: Drive PWN::AI::RedTeam::VectorAndEmbeddingWeaknesses from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::VectorAndEmbeddingWeaknesses
  source: pwn/ai/red_team/vector_and_embedding_weaknesses.rb
---

# PWN::AI::RedTeam::VectorAndEmbeddingWeaknesses

AI RedTeam Module used to test vector stores and embedding pipelines for inversion, tenant bleed, cache poison, and blocker documents (OWASP LLM09:2026).

## When to use

Call `PWN::AI::RedTeam::VectorAndEmbeddingWeaknesses` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/vector_and_embedding_weaknesses.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::VectorAndEmbeddingWeaknesses.help
PWN::AI::RedTeam::VectorAndEmbeddingWeaknesses.scan(opts)
```

## Public methods

- `scan`
- `security_references`
- `authors`
- `help`

## References

- `references/security.md` — CWE / NIST mapping
- `references/urls.md` — URLs from source

## Source

`pwn/ai/red_team/vector_and_embedding_weaknesses.rb`

## Verification

`PWN::AI::RedTeam::VectorAndEmbeddingWeaknesses.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
