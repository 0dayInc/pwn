---
name: pwn-aws-directoryservice
description: Drive PWN::AWS::DirectoryService from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::DirectoryService
  source: pwn/aws/directory_service.rb
---

# PWN::AWS::DirectoryService

This module provides a client for making API requests to AWS Directory Service.

## When to use

Call `PWN::AWS::DirectoryService` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/directory_service.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::DirectoryService.help
PWN::AWS::DirectoryService.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/directory_service.rb`

## Verification

`PWN::AWS::DirectoryService.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
