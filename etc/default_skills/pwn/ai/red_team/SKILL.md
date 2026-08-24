---
name: pwn-ai-redteam
description: Drive PWN::AI::RedTeam from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam
  source: pwn/ai/red_team.rb
---

# PWN::AI::RedTeam

This file, using the autoload directive loads AI RedTeam modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html PWN::AI::RedTeam is the AI/LLM analogue of PWN::SAST - a collection of adversarial test-case modules that exhaustively analyze / fuzz Large Language Models for AI-specific vulnerabilities (prompt injection, jailbreaks, system-prompt extraction, sensitive-data disclosure, excessive agency, insecure output handling, supply chain, poisoning, unbounded consumption, hidden context, vector stores, RAG, MCP/A2A, and memory persistence). Each module maps to an OWASP LLM Top-10 category and a MITRE ATLAS technique so findings roll straight into PWN::Reports::AIRedTeam.

## When to use

Call `PWN::AI::RedTeam` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam.help
PWN::AI::RedTeam.help(opts)
```

## Public methods

- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/red_team.rb`

## Verification

`PWN::AI::RedTeam.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
