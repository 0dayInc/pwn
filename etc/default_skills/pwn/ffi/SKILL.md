---
name: pwn-ffi
description: Drive PWN::FFI from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI
  source: pwn/ffi.rb
---

# PWN::FFI

This file, using the autoload directive loads FFI modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html Bindings under this namespace are *thin* — they attach functions from already-installed system shared objects (libliquid, libvolk, libfftw3f, librtlsdr, libhackrf, libSoapySDR) so PWN::SDR::Decoder::* can run MHz-rate DSP inner loops in native/SIMD code while Ruby stays in charge of orchestration. Nothing here shells out; nothing here compiles at `gem install` time. If a .so is missing the module still loads and `.available?` returns false so callers can fall back to pure Ruby.

## When to use

Call `PWN::FFI` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI.help
PWN::FFI.available(opts)
```

## Public methods

- `available`
- `backends`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ffi.rb`

## Verification

`PWN::FFI.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
