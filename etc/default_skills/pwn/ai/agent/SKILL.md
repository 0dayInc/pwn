---
name: pwn-ai-agent
description: Drive PWN::AI::Agent from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent
  source: pwn/ai/agent.rb
---

# PWN::AI::Agent

This file, using the autoload directive loads SAST modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

## When to use

Call `PWN::AI::Agent` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent.help
PWN::AI::Agent.help(opts)
```

## Public methods

- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/agent.rb`

## Verification

`PWN::AI::Agent.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
