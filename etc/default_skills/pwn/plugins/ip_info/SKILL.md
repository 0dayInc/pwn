---
name: pwn-plugins-ipinfo
description: Drive PWN::Plugins::IPInfo from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::IPInfo
  source: pwn/plugins/ip_info.rb
---

# PWN::Plugins::IPInfo

This plugin leverages ip-api.com's REST API to discover information about IP addresses 1,000 daily requests are allowed for free

## When to use

Call `PWN::Plugins::IPInfo` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/ip_info.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::IPInfo.help
PWN::Plugins::IPInfo.check_rfc1918(opts)
```

## Public methods

- `check_rfc1918`
- `get`
- `bruteforce_subdomains`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/ip_info.rb`

## Verification

`PWN::Plugins::IPInfo.respond_to?(:check_rfc1918)` after the
module is loaded. Read the source for parameter names.
