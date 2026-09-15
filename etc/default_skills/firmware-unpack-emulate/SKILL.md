---
name: firmware-unpack-emulate
description: Use when unpacking firmware. REDB on extracted bins.
---

# Firmware unpack and emulate

1. Unpack with binwalk/firmware-mod-kit outside the radio path.
2. `PWN::Plugins::REDB.open` on extracted userland binaries.
3. Emulate with qemu user; debug via `PWN::Plugins::Debugger.launch`.
