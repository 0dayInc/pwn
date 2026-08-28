---
name: pwn-reports-markdown
description: Drive PWN::Reports::Markdown from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::Markdown
  source: pwn/reports/markdown.rb
---

# PWN::Reports::Markdown

Generic Markdown report writer for pentest / findings payloads.

## When to use

Call `PWN::Reports::Markdown` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/markdown.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::Markdown.help
PWN::Reports::Markdown.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## Source

`pwn/reports/markdown.rb`

## Verification

`PWN::Reports::Markdown.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
