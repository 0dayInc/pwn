---
name: pwn-ai-agent-tools-findingrecord
description: Drive PWN::Ai::Agent::Tools::FindingRecord from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Ai::Agent::Tools::FindingRecord
  source: pwn/ai/agent/tools/finding_record.rb
---

# PWN::Ai::Agent::Tools::FindingRecord

Public API for PWN::Ai::Agent::Tools::FindingRecord.

## When to use

Call `PWN::Ai::Agent::Tools::FindingRecord` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/tools/finding_record.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Ai::Agent::Tools::FindingRecord.help
PWN::Ai::Agent::Tools::FindingRecord.help(opts)
```

## Public methods

- _(no public class methods parsed)_

## Source

`pwn/ai/agent/tools/finding_record.rb`

## Verification

`PWN::Ai::Agent::Tools::FindingRecord.respond_to?(:help)` after the
module is loaded. Read the source for parameter names.
