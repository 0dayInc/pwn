---
name: hardware-and-firmware-testing
description: Test firmware and hardware with OWASP FSTM/ISTG and PWN serial plugins.
license: MIT
allowed-tools: [pwn, terminal]
metadata:
  bundled: true
  references:
    - https://github.com/scriptingxss/owasp-fstm
    - https://owasp.org/www-project-iot-security-testing-guide/
    - https://owasp.org/owasp-istg/03_test_cases/firmware/
---

# Hardware and Firmware Testing

Use when the target is a device, PCB, UART/JTAG, RF dongle, or a firmware
image. Hand unpacked binaries to `reverse-engineering-binaries` and
crashes to `deep-exploitation`.

## When to use

- firmware dump, IoT, router image, MCU flash
- UART / SPI / I2C / JTAG / SWD
- RF / SDR path (`PWN::SDR`, `pwn_gqrx_scanner`)

## Methodologies

OWASP Firmware Security Testing Methodology (FSTM) - 9 stages:

1. Information gathering
2. Obtaining firmware
3. Analyzing firmware
4. Extracting the filesystem
5. Analyzing filesystem contents
6. Emulating firmware
7. Dynamic analysis
8. Runtime analysis
9. Binary exploitation

Also:

| Catalog | Role |
|---|---|
| OWASP ISTG | IoT device test cases (firmware chapter cites FSTM) |
| OSSTMM | physical + wireless + telecom channels |
| NIST SP 800-115 | evidence and reporting |
| CWE | 119, 798, 1278, 1326 for embedded flaws |

## Tooling

- Hardware: `PWN::Plugins::Serial`, `BusPirate`, `Android` (adb),
  `MSR206` when magstripe is in the ask
- RF: `PWN::SDR`, `pwn_gqrx_scanner`, Flipper helpers in SDR docs
- Extract: `binwalk`, `sasquatch`/`unsquashfs`, `firmware-mod-kit` if
  present
- RE: `file`, `strings`, `radare2`, `PWN::Plugins::Assembly`
- Emulate: QEMU user/system when the arch is known

## Procedure

1. FSTM-1: chip markings, FCC ID, model, debug headers. Photograph or
   note.
2. Obtain the image (vendor download, dump via UART/flash). Hash it.
3. `binwalk -e`, list filesystems, creds, keys, init scripts.
4. Emulate or boot if possible. Dynamic: default creds, open ports,
   update channel.
5. Runtime: attach serial, check root shell, busybox, leftover test
   hooks.
6. Binary: pick one sink, then `reverse-engineering-binaries` /
   `deep-exploitation`.
7. Report per FSTM stage with artefact paths.

## Pitfalls

- `strings` on a blob is not FSTM-complete.
- Do not brick the only sample. Prefer a copy / emulator.
- RF work stays on the named band/profile.

## Verification

Image hash + extract dir exist, at least two FSTM stages have evidence
beyond notes, and leftover secrets or sinks are cited from files that
were read back.
