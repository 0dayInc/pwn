---
name: pwn-plugins-nmapit
description: Drive PWN::Plugins::NmapIt from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::NmapIt
  source: pwn/plugins/nmap_it.rb
---

# PWN::Plugins::NmapIt

This plugin is used as an interface to nmap, the exploration tool and security / port scanner. More info on available options can be found at: https://github.com/postmodern/ruby-nmap/blob/main/lib/nmap/command.rb

## When to use

Call `PWN::Plugins::NmapIt` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/nmap_it.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::NmapIt.help
PWN::Plugins::NmapIt.port_scan(opts)
```

## Public methods

- `port_scan`
- `parse_xml_results`
- `diff_xml_results`
- `to_findings`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/nmap_it.rb`

## Verification

`PWN::Plugins::NmapIt.respond_to?(:port_scan)` after the
module is loaded. Read the source for parameter names.
