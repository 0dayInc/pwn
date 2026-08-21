---
name: pwn-ai-redteam-insecureoutputhandling
description: Drive PWN::AI::RedTeam::InsecureOutputHandling from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::InsecureOutputHandling
  source: pwn/ai/red_team/insecure_output_handling.rb
---

# PWN::AI::RedTeam::InsecureOutputHandling

AI RedTeam Module used to determine if a target LLM will emit unsanitized / active content (HTML, JS, shell, SQL, template expressions) that could lead to XSS, SSRF, RCE, or SQLi in a downstream consumer that trusts model output.

## When to use

Call `PWN::AI::RedTeam::InsecureOutputHandling` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/insecure_output_handling.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::InsecureOutputHandling.help
PWN::AI::RedTeam::InsecureOutputHandling.scan(opts)
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

`pwn/ai/red_team/insecure_output_handling.rb`

## Verification

`PWN::AI::RedTeam::InsecureOutputHandling.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
