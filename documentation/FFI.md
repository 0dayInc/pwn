# `PWN::FFI` — Native Calls

`PWN::FFI::Stdio` (`lib/pwn/ffi/stdio.rb`) exposes libc functions to Ruby via
the `ffi` gem — useful for shellcode testing, format-string research and
low-level RE without leaving the REPL.

```ruby
PWN::FFI::Stdio.printf(fmt: "leak: %p\n", args: [0x41414141])
```

Combine with `PWN::Plugins::Assembly` (opcodes ↔ asm) and `pwn-asm` for a
minimal in-process exploit-dev workbench.

[← Home](Home.md) · [Hardware](Hardware.md)
