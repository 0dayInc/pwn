---
name: pwn-ai-agent-vulngen
description: Drive PWN::AI::Agent::VulnGen from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::VulnGen
  source: pwn/ai/agent/vuln_gen.rb
---

# PWN::AI::Agent::VulnGen

This module is an AI agent designed to analyze generic vulnerability descriptions and generate detailed security findings following the exact bug bounty writeup structure: 1. Detailed finding description with technical depth and PoC when possible 2. Business impact 3. Remediation recommendations, including compensating controls / stop gaps 4. CVSS score, vector string, and first.org calculator URI 5. CWE category, brief description, and CWE URI 6. Relevant NIST 800-53 control It leverages the PWN::AI::Agent::Reflect.on method. Defaults to Jira for existing workflow compatibility.

## When to use

Call `PWN::AI::Agent::VulnGen` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/vuln_gen.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::VulnGen.help
PWN::AI::Agent::VulnGen.analyze(opts)
```

## Public methods

- `analyze`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/agent/vuln_gen.rb`

## Verification

`PWN::AI::Agent::VulnGen.respond_to?(:analyze)` after the
module is loaded. Read the source for parameter names.
