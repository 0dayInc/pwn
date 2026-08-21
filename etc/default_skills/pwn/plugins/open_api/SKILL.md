---
name: pwn-plugins-openapi
description: Drive PWN::Plugins::OpenAPI from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::OpenAPI
  source: pwn/plugins/open_api.rb
---

# PWN::Plugins::OpenAPI

Module to interact with OpenAPI specifications, merging multiple specs while resolving schema dependencies and ensuring OpenAPI compliance.

## When to use

Call `PWN::Plugins::OpenAPI` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/open_api.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::OpenAPI.help
PWN::Plugins::OpenAPI.generate_spec(opts)
```

## Public methods

- `generate_spec`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/open_api.rb`

## Verification

`PWN::Plugins::OpenAPI.respond_to?(:generate_spec)` after the
module is loaded. Read the source for parameter names.
