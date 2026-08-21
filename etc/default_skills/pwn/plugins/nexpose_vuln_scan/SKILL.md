---
name: pwn-plugins-nexposevulnscan
description: Drive PWN::Plugins::NexposeVulnScan from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::NexposeVulnScan
  source: pwn/plugins/nexpose_vuln_scan.rb
---

# PWN::Plugins::NexposeVulnScan

This plugin is used for interacting w/ Nexpose using the Nexpose API.

## When to use

Call `PWN::Plugins::NexposeVulnScan` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/nexpose_vuln_scan.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::NexposeVulnScan.help
PWN::Plugins::NexposeVulnScan.login(opts)
```

## Public methods

- `login`
- `list_all_individual_site_assets`
- `update_site_assets`
- `delete_site_assets_older_than`
- `scan_site_by_name`
- `generate_report_via_existing_config`
- `download_recurring_report`
- `logout`
- `authors`
- `help`

## Source

`pwn/plugins/nexpose_vuln_scan.rb`

## Verification

`PWN::Plugins::NexposeVulnScan.respond_to?(:login)` after the
module is loaded. Read the source for parameter names.
