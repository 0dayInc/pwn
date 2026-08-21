---
name: pwn-aws-cloudwatchlogs
description: Drive PWN::AWS::CloudWatchLogs from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CloudWatchLogs
  source: pwn/aws/cloud_watch_logs.rb
---

# PWN::AWS::CloudWatchLogs

This module provides a client for making API requests to Amazon CloudWatch Logs.

## When to use

Call `PWN::AWS::CloudWatchLogs` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cloud_watch_logs.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CloudWatchLogs.help
PWN::AWS::CloudWatchLogs.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cloud_watch_logs.rb`

## Verification

`PWN::AWS::CloudWatchLogs.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
