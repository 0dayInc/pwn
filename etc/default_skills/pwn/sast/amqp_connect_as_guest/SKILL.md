---
name: pwn-sast-amqpconnectasguest
description: Drive PWN::SAST::AMQPConnectAsGuest from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::AMQPConnectAsGuest
  source: pwn/sast/amqp_connect_as_guest.rb
---

# PWN::SAST::AMQPConnectAsGuest

SAST Module used to detect connection references within source code to determine if connections to RabbitMQ servers are using guest accounts.

## When to use

Call `PWN::SAST::AMQPConnectAsGuest` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/amqp_connect_as_guest.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::AMQPConnectAsGuest.help
PWN::SAST::AMQPConnectAsGuest.scan(opts)
```

## Public methods

- `scan`
- `security_references`
- `authors`
- `help`

## References

- `references/security.md` — CWE / NIST mapping
- `references/urls.md` — URLs from source

## Source

`pwn/sast/amqp_connect_as_guest.rb`

## Verification

`PWN::SAST::AMQPConnectAsGuest.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
