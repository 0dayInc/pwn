---
name: reverse-engineering-binaries
description: Triage a binary with checksec, disassembly, and PWN::Plugins::Assembly.
license: MIT
allowed-tools: [pwn, terminal]
metadata:
  bundled: true
  references:
    - CWE-119
    - CWE-676
---

# Reverse Engineering Binaries

Use when the ask is to understand a binary, firmware blob, or opcode
stream. Use `deep-exploitation` after you have a crash or a primitive.

## When to use

- "what is this ELF / PE / Mach-O"
- recover strings, imports, mitigations, or a function algorithm
- assemble / disassemble via `PWN::Plugins::Assembly` or `pwn-asm`

## Methodologies

- NIST SP 800-115: target analysis / static+dynamic review
- OWASP FSTM stages 1-6 when the file is firmware (then
  `hardware-and-firmware-testing`)
- CWE-119 / CWE-676 / CWE-416 for sink notes
- MITRE ATT&CK Execution / Discovery labels in the write-up

## Tooling

- File: `file`, `readelf -a`, `objdump -d`, `strings -n 8`, `nm`, `ldd`.
- Mitigations: `checksec --file=BIN`.
- RE: `radare2` / Cutter, Ghidra, IDA as installed.
- Dynamic: `strace`, `ltrace`, gdb.
- PWN: `PWN::Plugins::Assembly` (asm <-> opcodes, multi-arch),
  `BannedFunctionCallsC` / `UseAfterFree` SAST on available source,
  `PWN::Plugins::Fuzz` if you move to crash-finding.

```ruby
PWN::Plugins::Assembly.opcodes_to_asm(opcodes: '90 90', arch: 'x86_64')
PWN::Plugins::Assembly.asm_to_opcodes(asm: 'nop', arch: 'x86_64')
```

## Procedure

1. `file` + hashes. Note arch, linking, stripped or not.
2. `checksec` / `readelf -l` for NX, PIE, RELRO, canary, rpath.
3. `strings` + import table (`readelf -d` / `objdump -T`) for the
   interesting surface (crypto, net, parser, `system`/`strcpy`).
4. Locate the function (symbols, strings xrefs, entry). Disassemble.
5. If packed, unpack first (UPX or a loader dump) - do not invent
   control flow from a packed blob.
6. Write notes: purpose, inputs, dangerous sinks, unanswered questions.
7. Hand off to `deep-exploitation` only when you have a sink + control.

## Pitfalls

- Do not paste a 4k disassembly as the answer. Summarize, keep the
  artefact on disk, read it back.
- Firmware without a known base address is not "fully reversed" after
  one `strings`.
- `pwn-asm` is for opcode work, not a substitute for `checksec`.

## Verification

Notes on disk (or in the final) include arch, mitigations, and at least
one concrete function or sink with evidence from the tools above.
