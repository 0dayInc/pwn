---
name: pwn-aws-cloudwatchevents
description: Drive PWN::AWS::CloudWatchEvents from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CloudWatchEvents
  source: pwn/aws/cloud_watch_events.rb
---

# PWN::AWS::CloudWatchEvents

This module provides a client for making API requests to Amazon CloudWatch Events.

## When to use

Call `PWN::AWS::CloudWatchEvents` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cloud_watch_events.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CloudWatchEvents.help
PWN::AWS::CloudWatchEvents.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cloud_watch_events.rb`

## Verification

`PWN::AWS::CloudWatchEvents.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
