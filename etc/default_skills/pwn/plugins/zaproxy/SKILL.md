---
name: pwn-plugins-zaproxy
description: Drive PWN::Plugins::Zaproxy from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Zaproxy
  source: pwn/plugins/zaproxy.rb
---

# PWN::Plugins::Zaproxy

This plugin converts images to readable text TODO: Convert all rest requests to POST instead of GET

## When to use

Call `PWN::Plugins::Zaproxy` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/zaproxy.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Zaproxy.help
PWN::Plugins::Zaproxy.start(opts)
```

## Public methods

- `start`
- `import_openapi_to_sitemap`
- `get_sitemap`
- `add_to_scope`
- `requester`
- `spider`
- `inject_additional_http_headers`
- `active_scan`
- `get_alerts`
- `generate_scan_report`
- `breakpoint`
- `tamper`
- `stop`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/zaproxy.rb`

## Verification

`PWN::Plugins::Zaproxy.respond_to?(:start)` after the
module is loaded. Read the source for parameter names.
