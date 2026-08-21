---
name: pwn-sast-apachefilesystemutilapi
description: Drive PWN::SAST::ApacheFileSystemUtilAPI from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::ApacheFileSystemUtilAPI
  source: pwn/sast/apache_file_system_util_api.rb
---

# PWN::SAST::ApacheFileSystemUtilAPI

SAST Module used to identify arbitrary command execution within Apache Common's API Class, org.apache.commons.io.FileSystemUtils

## When to use

Call `PWN::SAST::ApacheFileSystemUtilAPI` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/apache_file_system_util_api.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::ApacheFileSystemUtilAPI.help
PWN::SAST::ApacheFileSystemUtilAPI.scan(opts)
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

`pwn/sast/apache_file_system_util_api.rb`

## Verification

`PWN::SAST::ApacheFileSystemUtilAPI.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
