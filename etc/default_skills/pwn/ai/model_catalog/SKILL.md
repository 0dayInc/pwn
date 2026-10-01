---
name: pwn-ai-modelcatalog
description: Drive PWN::AI::ModelCatalog from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::ModelCatalog
  source: pwn/ai/model_catalog.rb
---

# PWN::AI::ModelCatalog

Shared catalog lookup for provider model records. Each provider still fetches its own payload; this only finds one named row without a second network call when the caller already has the list.

## When to use

Call `PWN::AI::ModelCatalog` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/model_catalog.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::ModelCatalog.help
PWN::AI::ModelCatalog.find_row(opts)
```

## Public methods

- `find_row`
- `catalog_rows`
- `model_row`
- `parse_row`
- `lookup_opts`
- `authors`
- `help`
- `model_row?`

## Source

`pwn/ai/model_catalog.rb`

## Verification

`PWN::AI::ModelCatalog.respond_to?(:find_row)` after the
module is loaded. Read the source for parameter names.
