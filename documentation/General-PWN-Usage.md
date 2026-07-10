# General Usage - Day-One Cheat Sheet

## Launch

```bash
$ pwn                         # interactive REPL
$ pwn --ai "scan 10.0.0.0/24 with NmapIt and summarise open services"
$ pwn_nmap_discover_tcp_udp -t 10.0.0.0/24 -o out/   # headless driver
```

## Check / provision this host

```bash
$ pwn setup                   # doctor: which PWN:: capabilities are usable here?
$ pwn setup --profile web     # install what TransparentBrowser / Burp / ZAP need
$ pwn setup --list-profiles   # core · ai · web · net · db · sdr · vision · voice · exploit · hardware · full
```

See [Installation](Installation.md) for every flag and the `PWN::Setup` API.

## Inside the REPL

```ruby
PWN.help                            # top-level help
PWN::Plugins.constants.sort         # list all 66 plugins
PWN::Plugins::NmapIt.help           # per-plugin usage
PWN::Setup.check                    # capability doctor from inside the REPL
ls PWN::Plugins::BurpSuite          # Pry: list methods
show-source PWN::SAST::SQL.scan     # Pry: read the code
history                             # what you've typed → copy into a driver
```

## Custom REPL commands

| Command | Does |
|---|---|
| `pwn-ai` | Enter the agent TUI (SHIFT+ENTER = newline, ENTER = submit) |
| `pwn-asm` | Multi-line assembly ↔ opcode workbench |
| `pwn-vault` | Decrypt → edit `~/.pwn/pwn.yaml` in `$EDITOR` → re-encrypt |
| `pwn-ai-memory` | Inspect / edit `~/.pwn/memory.json` |
| `pwn-ai-sessions` | List / view / delete transcripts |
| `pwn-ai-cron` | List / run scheduled jobs |
| `pwn-ai-delegate` | Hand a task to a Swarm persona |
| `welcome-banner` | Redraw a random `PWN::Banner` |
| `toggle-pager` | Pry pager on/off |

## A 60-second attack chain

```ruby
# 1. discover
nmap = PWN::Plugins::NmapIt.port_scan(target: 'scanme.nmap.org')

# 2. drive traffic through Burp
burp = PWN::Plugins::BurpSuite.start(headless: true)
b    = PWN::Plugins::TransparentBrowser.open(
         browser_type: :headless, proxy: 'http://127.0.0.1:8080')
b[:browser].goto 'http://scanme.nmap.org'

# 3. active scan
scan = PWN::Plugins::BurpSuite.active_scan(burp_obj: burp,
         target_url: 'http://scanme.nmap.org')

# 4. report
PWN::Reports::SAST.generate(dir_path: '/tmp/src', output_dir: '/tmp/out')
```

Then say the same thing in English inside `pwn-ai` and watch the agent do it.

**Next:** [pwn REPL](pwn-REPL.md) · [pwn-ai Agent](pwn-ai-Agent.md) ·
[CLI Drivers](CLI-Drivers.md)

[← Home](Home.md)
