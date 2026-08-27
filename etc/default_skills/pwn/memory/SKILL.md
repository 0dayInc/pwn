---
name: pwn-memory
description: Drive PWN::Memory from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Memory
  source: pwn/memory.rb
---

# PWN::Memory

PWN::Memory provides persistent cross-session memory for the pwn-ai agent. Facts, user preferences, environment details, lessons learned, and task state are stored in ~/.pwn/memory.json and survive across REPL restarts / pwn-ai sessions. The pwn-ai agent (in agent mode) automatically receives relevant memory injected into its system prompt. The agent can also call remember/recall via ruby code blocks during execution loops.

## When to use

Call `PWN::Memory` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/memory.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Memory.help
PWN::Memory.load(opts)
```

## Public methods

- `load`
- `save`
- `remember`
- `recall`
- `current_session_id`
- `session_turns`
- `recent_dialog`
- `prior_user_message`
- `prior_assistant_message`
- `turn_pairs`
- `find_turn_pair`
- `meta_recall_user`
- `meta_recall_assistant`
- `normalize_utterance`
- `recall_semantic`
- `forget`
- `clear`
- `to_context`
- `protected_entry`
- `lean`
- `authors`
- `help`
- `lean!`
- `meta_recall_assistant?`
- `meta_recall_user?`
- `protected_entry?`

## Source

`pwn/memory.rb`

## Verification

`PWN::Memory.respond_to?(:load)` after the
module is loaded. Read the source for parameter names.
