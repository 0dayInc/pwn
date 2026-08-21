---
name: pwn-plugins-packet
description: Drive PWN::Plugins::Packet from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Packet
  source: pwn/plugins/packet.rb
---

# PWN::Plugins::Packet

This plugin is used for interacting with PCAP files to map out and visualize in an automated fashion what comprises a infrastructure, network, and/or application

## When to use

Call `PWN::Plugins::Packet` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/packet.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Packet.help
PWN::Plugins::Packet.open_pcap_file(opts)
```

## Public methods

- `open_pcap_file`
- `construct_arp`
- `construct_eth`
- `construct_hsrp`
- `construct_icmp`
- `construct_icmpv6`
- `construct_ip`
- `construct_ipv6`
- `construct_tcp`
- `construct_udp`
- `send`
- `authors`
- `help`

## Source

`pwn/plugins/packet.rb`

## Verification

`PWN::Plugins::Packet.respond_to?(:open_pcap_file)` after the
module is loaded. Read the source for parameter names.
