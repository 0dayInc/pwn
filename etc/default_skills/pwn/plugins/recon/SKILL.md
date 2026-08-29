---
name: pwn-plugins-recon
description: Drive PWN::Plugins::Recon from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Recon
  source: pwn/plugins/recon.rb
---

# PWN::Plugins::Recon

subfinder/httpx/masscan wrappers + cert-transparency (crt.sh, certspotter).

## When to use

Call `PWN::Plugins::Recon` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/recon.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Recon.help
PWN::Plugins::Recon.required_bins(opts)
```

## Public methods

- `required_bins`
- `subdomains`
- `httpx`
- `masscan`
- `crt_sh`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/recon.rb`

## Verification

`PWN::Plugins::Recon.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
