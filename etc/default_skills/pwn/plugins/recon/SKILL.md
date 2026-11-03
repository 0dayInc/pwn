---
name: pwn-plugins-recon
description: Drive PWN::Plugins::Recon from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  preserve: true
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

Pass an explicit `yubikey: {slot: 2, serial: '12345678', timeout: 30}` to `run`
or `harvest_loot` to encrypt harvested credentials with an already provisioned
HMAC-SHA1 OTP slot. Both entry points preserve the selector through Vault.ingest.
Device failure raises without falling back to a software master key. Raw scan
evidence remains governed by the existing recon persistence contract; selecting
hardware loot protection does not encrypt the entire asset/evidence directory.

Verify offline with a fake banner and a stubbed 20-byte challenge-response; assert
the saved loot envelope has the hardware KDF and no `.pwn-vault.key` is created.

```ruby
PWN::Plugins::Recon.help
PWN::Plugins::Recon.required_bins
```

## Public methods

- `required_bins`
- `run`
- `subdomains`
- `httpx`
- `masscan`
- `crt_sh`
- `amass`
- `passive_dns`
- `harvest_loot`
- `observe`
- `observations`
- `known_ports`
- `handoff`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/recon.rb`

## Verification

`PWN::Plugins::Recon.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
