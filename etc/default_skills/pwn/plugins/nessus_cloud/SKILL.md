---
name: pwn-plugins-nessuscloud
description: Drive PWN::Plugins::NessusCloud from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::NessusCloud
  source: pwn/plugins/nessus_cloud.rb
---

# PWN::Plugins::NessusCloud

This plugin is used for interacting w/ the Tenable.io REST API (i.e. Nessus Cloud)

## When to use

Call `PWN::Plugins::NessusCloud` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/nessus_cloud.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::NessusCloud.help
PWN::Plugins::NessusCloud.login(opts)
```

## Public methods

- `login`
- `get_canned_scan_templates`
- `get_policies`
- `get_folders`
- `get_scanners`
- `get_target_networks`
- `get_timezones`
- `get_target_groups`
- `get_tag_values`
- `get_assets`
- `add_tag_to_assets`
- `get_credential_types`
- `get_scans`
- `create_scan`
- `update_scan`
- `launch_scan`
- `get_scan_status`
- `create_tag`
- `get_scan_history`
- `export_scan_results`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/nessus_cloud.rb`

## Verification

`PWN::Plugins::NessusCloud.respond_to?(:login)` after the
module is loaded. Read the source for parameter names.
