---
name: pwn-aws-iotdataplane
description: Drive PWN::AWS::IoTDataPlane from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::IoTDataPlane
  source: pwn/aws/iot_data_plane.rb
---

# PWN::AWS::IoTDataPlane

This module provides a client for making API requests to AWS IoT Data Plane.

## When to use

Call `PWN::AWS::IoTDataPlane` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/iot_data_plane.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::IoTDataPlane.help
PWN::AWS::IoTDataPlane.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/iot_data_plane.rb`

## Verification

`PWN::AWS::IoTDataPlane.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
