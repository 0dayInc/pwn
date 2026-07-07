# Hardware & Physical-Layer Hacking

![Hardware hacking](diagrams/hardware-hacking.svg)
![Reverse engineering](diagrams/reverse-engineering-flow.svg)

## Serial / Bus

| Module | Use |
|---|---|
| `PWN::Plugins::Serial` | Generic UART (`/dev/ttyUSB*`) — read/write, baud detect |
| `PWN::Plugins::BusPirate` | SPI/I²C/1-Wire via Bus Pirate |
| `PWN::Plugins::MSR206` | ISO magstripe read/write (tracks 1-3) |

CLI: `pwn_serial_msr206`, `pwn_serial_qualcomm_commands`,
`pwn_serial_check_voicemail`, `pwn_serial_son_micro_sm132_rfid`

## Mobile

`PWN::Plugins::Android` — `adb_net_connect`, `adb_sh`, `adb_push/pull`,
`take_screenshot`, `screen_record`, `list_installed_apps`, `dumpsys`,
`open_app`, `find_hidden_codes`, `swipe`, `input`, `input_special`,
`invoke_event_listener`. CLI war-dialer: `pwn_android_war_dialer`.

## Voice / Telephony

`PWN::Plugins::BareSIP` (SIP recon/war-dial), `PWN::Plugins::Voice` (TTS).
CLI: `pwn_phone`.

## Radio

See [SDR](SDR.md) — GQRX, FlipperZero, RFIDler, SonMicro.

## Binary / RE

- `PWN::Plugins::XXD` — hex dump / patch
- `PWN::Plugins::Assembly` + `pwn-asm` REPL — opcodes ↔ asm, multi-arch
- `PWN::Plugins::BlackDuckBinaryAnalysis` — SBOM + CVE match on firmware
- [`PWN::FFI`](FFI.md) — call libc from Ruby

[← Home](Home.md) · [SDR](SDR.md) · [FFI](FFI.md)
