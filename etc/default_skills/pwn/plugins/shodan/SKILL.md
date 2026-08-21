---
name: pwn-plugins-shodan
description: Drive PWN::Plugins::Shodan from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Shodan
  source: pwn/plugins/shodan.rb
---

# PWN::Plugins::Shodan

This plugin is used for interacting w/ Shodan's REST API using the 'rest' browser type of PWN::Plugins::TransparentBrowser. This is based on the following Shodan API Specification: https://developer.shodan.io/api

## When to use

Call `PWN::Plugins::Shodan` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/shodan.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Shodan.help
PWN::Plugins::Shodan.services_by_ips(opts)
```

## Public methods

- `services_by_ips`
- `query_result_totals`
- `search`
- `tokens`
- `ports_shodan_crawls`
- `list_on_demand_scan_protocols`
- `scan_network`
- `scan_internet`
- `scan_status`
- `services_shodan_crawls`
- `saved_search_queries`
- `most_popular_tags`
- `my_profile`
- `my_pub_ip`
- `api_info`
- `honeypot_probability_scores`
- `get_uris`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/shodan.rb`

## Verification

`PWN::Plugins::Shodan.respond_to?(:services_by_ips)` after the
module is loaded. Read the source for parameter names.
