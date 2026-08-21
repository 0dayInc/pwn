---
name: pwn-aws-applicationdiscoveryservice
description: Drive PWN::AWS::ApplicationDiscoveryService from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ApplicationDiscoveryService
  source: pwn/aws/application_discovery_service.rb
---

# PWN::AWS::ApplicationDiscoveryService

This module provides a client for making API requests to AWS Application Discovery Service.

## When to use

Call `PWN::AWS::ApplicationDiscoveryService` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/application_discovery_service.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ApplicationDiscoveryService.help
PWN::AWS::ApplicationDiscoveryService.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/application_discovery_service.rb`

## Verification

`PWN::AWS::ApplicationDiscoveryService.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
