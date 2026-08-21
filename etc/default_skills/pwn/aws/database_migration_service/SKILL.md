---
name: pwn-aws-databasemigrationservice
description: Drive PWN::AWS::DatabaseMigrationService from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::DatabaseMigrationService
  source: pwn/aws/database_migration_service.rb
---

# PWN::AWS::DatabaseMigrationService

This module provides a client for making API requests to AWS Database Migration Service.

## When to use

Call `PWN::AWS::DatabaseMigrationService` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/database_migration_service.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::DatabaseMigrationService.help
PWN::AWS::DatabaseMigrationService.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/database_migration_service.rb`

## Verification

`PWN::AWS::DatabaseMigrationService.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
