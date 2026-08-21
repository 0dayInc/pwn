---
name: pwn-plugins-burpsuite
description: Drive PWN::Plugins::BurpSuite from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::BurpSuite
  source: pwn/plugins/burp_suite.rb
---

# PWN::Plugins::BurpSuite

This plugin was created to interact w/ Burp Suite Pro in headless mode to kick off spidering/live scanning

## When to use

Call `PWN::Plugins::BurpSuite` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/burp_suite.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::BurpSuite.help
PWN::Plugins::BurpSuite.start(opts)
```

## Public methods

- `start`
- `in_scope`
- `add_to_scope`
- `spider`
- `enable_proxy`
- `disable_proxy`
- `get_proxy_listeners`
- `add_proxy_listener`
- `update_proxy_listener`
- `delete_proxy_listener`
- `get_proxy_history`
- `update_proxy_history`
- `get_websocket_history`
- `update_websocket_history`
- `get_sitemap`
- `add_to_sitemap`
- `update_sitemap`
- `import_openapi_to_sitemap`
- `active_scan`
- `get_scan_issues`
- `add_repeater_tab`
- `get_all_repeater_tabs`
- `get_repeater_tab`
- `send_repeater_request`
- `update_repeater_tab`
- `delete_repeater_tab`
- `generate_scan_report`
- `update_burp_jar`
- `stop`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/burp_suite.rb`

## Verification

`PWN::Plugins::BurpSuite.respond_to?(:start)` after the
module is loaded. Read the source for parameter names.
