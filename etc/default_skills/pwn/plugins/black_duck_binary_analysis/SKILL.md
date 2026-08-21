---
name: pwn-plugins-blackduckbinaryanalysis
description: Drive PWN::Plugins::BlackDuckBinaryAnalysis from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::BlackDuckBinaryAnalysis
  source: pwn/plugins/black_duck_binary_analysis.rb
---

# PWN::Plugins::BlackDuckBinaryAnalysis

This plugin is used for interacting w/ the Black Duck Binary Analysis REST API using the 'rest' browser type of PWN::Plugins::TransparentBrowser. This is based on the following Black Duck Binary Analysis API Specification: https://protecode-sc.com/help/api

## When to use

Call `PWN::Plugins::BlackDuckBinaryAnalysis` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/black_duck_binary_analysis.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::BlackDuckBinaryAnalysis.help
PWN::Plugins::BlackDuckBinaryAnalysis.get_apps(opts)
```

## Public methods

- `get_apps`
- `get_apps_by_group`
- `upload_file`
- `get_product`
- `abort_product_scan`
- `generate_product_report`
- `get_tasks`
- `get_groups`
- `create_group`
- `get_group_details`
- `get_group_statistics`
- `delete_group`
- `get_licenses`
- `get_component_licenses`
- `get_tags`
- `get_vulnerabilities`
- `get_components`
- `get_vendor_vulns`
- `get_audit_trail`
- `get_status`
- `get_service_info`
- `get_service_version`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/black_duck_binary_analysis.rb`

## Verification

`PWN::Plugins::BlackDuckBinaryAnalysis.respond_to?(:get_apps)` after the
module is loaded. Read the source for parameter names.
