---
name: pwn-ai-redteam-agentprotocolabuse
description: Drive PWN::AI::RedTeam::AgentProtocolAbuse from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::AgentProtocolAbuse
  source: pwn/ai/red_team/agent_protocol_abuse.rb
---

# PWN::AI::RedTeam::AgentProtocolAbuse

AI RedTeam Module used to simulate malicious MCP, A2A, and tool-connection channels: spoofed servers, poisoned tool descriptions, and confused-deputy tool calls.

## When to use

Call `PWN::AI::RedTeam::AgentProtocolAbuse` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/agent_protocol_abuse.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::AgentProtocolAbuse.help
PWN::AI::RedTeam::AgentProtocolAbuse.scan(opts)
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

`pwn/ai/red_team/agent_protocol_abuse.rb`

## Verification

`PWN::AI::RedTeam::AgentProtocolAbuse.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
