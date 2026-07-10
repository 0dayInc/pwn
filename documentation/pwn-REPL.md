# The `pwn` REPL

`pwn` launches a **Pry** session with the entire `PWN::` namespace already
`require`d, a themed prompt, a persistent history file, and a set of custom
commands.

![REPL prototyping](diagrams/pwn-repl-prototyping.svg)

## Why Pry (not IRB)?

- `ls PWN::Plugins::BurpSuite` - instant method listing
- `show-source` / `show-doc` - read any plugin without leaving the shell
- `edit -m` - patch a method live and retry
- `wtf?` - full backtrace of the last exception
- `history --replay 5..12` - re-run a range of lines

## Custom commands

| Command | Implemented in | Purpose |
|---|---|---|
| `pwn-ai` | `Agent::Loop` | Enter the AI agent TUI |
| `pwn-vault` | `PWN::Plugins::Vault` | Decrypt → edit `~/.pwn/pwn.yaml` → re-encrypt |
| `pwn-asm` | `Plugins::Assembly` | Multiline asm ↔ opcodes workbench |
| `pwn-ai-memory` | `PWN::Memory` | View/edit persistent memory |
| `pwn-ai-sessions` | `PWN::Sessions` | List/view/delete transcripts |
| `pwn-ai-cron` | `PWN::Cron` | List/run/toggle scheduled jobs |
| `pwn-ai-delegate` | `Agent::Swarm` | Send one request to a persona |
| `welcome-banner` | `PWN::Banner` | Redraw a random banner |
| `toggle-pager` | Pry | Page long output on/off |

## Multi-line input

`pwn-ai` and `pwn-asm` use a custom `PWNMultiLineInput` reader:

- **SHIFT + ENTER** → insert newline
- **ENTER** → submit

> **tmux users:** requires `set -s extended-keys on` **and**
> `set -as terminal-features '<outerTERM>*:extkeys'` - see
> [Troubleshooting](Troubleshooting.md#shiftenter-submits-instead-of-newline).

## History → Driver

`~/.pwn_history` captures every line you type. When a sequence works, turn it
into a shipped `bin/pwn_*` driver - see
[From REPL History to Driver](Drivers.md).

**Next:** [pwn-ai Agent](pwn-ai-Agent.md) · [CLI Drivers](CLI-Drivers.md)

[← Home](Home.md)
