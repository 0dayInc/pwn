---
name: pwn-plugins-rabbitmq
description: Drive PWN::Plugins::RabbitMQ from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::RabbitMQ
  source: pwn/plugins/rabbit_mq.rb
---

# PWN::Plugins::RabbitMQ

This plugin is used to interact w/ RabbitMQ via ruby.

## When to use

Call `PWN::Plugins::RabbitMQ` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/rabbit_mq.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::RabbitMQ.help
PWN::Plugins::RabbitMQ.open(opts)
```

## Public methods

- `open`
- `close`
- `authors`
- `help`

## Source

`pwn/plugins/rabbit_mq.rb`

## Verification

`PWN::Plugins::RabbitMQ.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
