---
name: pwn-plugins-mitmproxy
description: Drive PWN::Plugins::MitmProxy from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::MitmProxy
  source: pwn/plugins/mitm_proxy.rb
---

# PWN::Plugins::MitmProxy

Native HTTP interception and opaque CONNECT tunnelling. CONNECT traffic is not decrypted: HAR explicitly marks the tunnel as metadata-only.

## When to use

Call `PWN::Plugins::MitmProxy` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/mitm_proxy.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::MitmProxy.help
PWN::Plugins::MitmProxy.start(opts)
```

## Public methods

- `start`
- `stop`
- `entries`
- `rules`
- `http_replay`
- `exchange`
- `replay`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/mitm_proxy.rb`

## Verification

`PWN::Plugins::MitmProxy.respond_to?(:start)` after the
module is loaded. Read the source for parameter names.
