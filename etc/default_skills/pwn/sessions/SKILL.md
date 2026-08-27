---
name: pwn-sessions
description: Drive PWN::Sessions from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Sessions
  source: pwn/sessions.rb
---

# PWN::Sessions

PWN::Sessions provides session management for pwn-ai (and other drivers) — list, resume, transcripts, and stats. Sessions are stored as JSONL transcripts in ~/.pwn/sessions/ for durability and easy search/append. pwn-ai agent mode auto-creates and appends to a session on each activation.

## When to use

Call `PWN::Sessions` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sessions.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Sessions.help
PWN::Sessions.sessions_dir(opts)
```

## Public methods

- `sessions_dir`
- `list`
- `create`
- `append`
- `load`
- `previous_id`
- `recall`
- `to_response_history`
- `to_llm_messages`
- `delete`
- `stats`
- `lean`
- `protected_session_ids`
- `authors`
- `help`
- `lean!`

## Source

`pwn/sessions.rb`

## Verification

`PWN::Sessions.respond_to?(:sessions_dir)` after the
module is loaded. Read the source for parameter names.
