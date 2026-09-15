---
name: kernel-pwn-triage
description: Use when triaging kernel bugs. Debugger and REDB first.
---

# Kernel pwn triage

1. `PWN::Plugins::REDB.open(bin: vmlinux)` then `funcs` / `xrefs_to`.
2. `PWN::Plugins::Debugger.attach(host: '127.0.0.1', port: 1234)` to a QEMU gdbstub (`-s`).
3. `break(addr_or_sym: 'commit_creds')`, `continue`, `regs`, `backtrace`.
4. Record findings with evidence paths; do not guess offsets.
