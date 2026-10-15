# General Usage - Day-One Cheat Sheet

## Launch

```bash
$ pwn                         # interactive REPL
$ pwn --ai "scan 10.0.0.0/24 with NmapIt and summarize open services"
$ pwn_nmap_discover_tcp_udp -t 10.0.0.0/24 -o out/   # headless driver
```

## Check / provision this host

```bash
$ pwn setup                   # doctor: which PWN:: capabilities are usable here?
$ pwn setup --profile web     # install what TransparentBrowser / Burp / ZAP need
$ pwn setup --list-profiles   # core · ai · web · net · db · sdr · vision · voice · exploit · hardware · full
$ pwn setup --migrate --fix   # after `gem update pwn`: verify + autofix ~/.pwn state
```

See [Installation](Installation.md) for every flag and the
`PWN::Setup` / `PWN::Migrate` API.

## Inside the REPL

```ruby
PWN.help                            # top-level help
PWN::Plugins.constants.sort         # list all 67 plugins
PWN::Plugins::NmapIt.help           # per-plugin usage
PWN::Setup.check                    # capability doctor from inside the REPL
PWN::Migrate.status                 # ~/.pwn state-file compatibility rows
ls PWN::Plugins::BurpSuite          # Pry: list methods
show-source PWN::SAST::SQL.scan     # Pry: read the code
history                             # what you've typed → copy into a driver
```

## Custom REPL commands

| Command | Does |
|---|---|
| `pwn-ai` | Enter the agent TUI (SHIFT+ENTER = newline, ENTER = submit) |
| `pwn-asm` | Multi-line assembly ↔ opcode workbench |
| `pwn-mesh` | Meshtastic serial / bluetooth / TCP / MQTT client (Ruby ≥ 4.0) |
| `pwn-vault` | Decrypt → edit `~/.pwn/pwn.yaml` in `$EDITOR` → re-encrypt |
| `pwn-ai-memory` | Inspect / edit `~/.pwn/memory.json` |
| `pwn-ai-sessions` | List / view / delete transcripts |
| `pwn-ai-cron` | List / run scheduled jobs |
| `pwn-ai-delegate` | Hand a task to a Swarm persona |
| `toggle-debug` | Stage log per request to `/tmp/pwn-ai-DEBUG-<SESSION_ID>-RN.log` |
| `toggle-trace` | Same as `toggle-debug` plus TracePoint; ENTER after each loop step. Pry.config, not Env. Off turns both off. |
| `toggle-pwn-ai-speaks` | TTS every final answer on/off |
| `welcome-banner` | Redraw a random `PWN::Banner` |
| `toggle-pager` | Pry pager on/off |

### Concurrent mesh reception and reply routing

`pwn-mesh` keeps the selected primary transport for manual TX and RX. A
nonempty `plugins.meshtastic.mqtt` configuration also opens an independent
MQTT receiver when the primary is Serial, Bluetooth, or TCP. Missing/empty
MQTT configuration makes no additional connection attempt; primary MQTT uses
only one subscription. MQTT connection failures leave the primary usable and
are reported in the UI. `/transport` reconnects both subscriptions; `/back`
closes them. Ctrl+T switches the active pane between COMPOSE and
CONVERSATION. COMPOSE keeps Up/Down history. CONVERSATION scrolls with
Up/Down one row, PgUp/PgDn a page, Home to the top, and End to the live
bottom. The live bottom is not row 0, so PgDn there stays put. Typing or
Enter returns to COMPOSE; Enter does not send while CONVERSATION is active.
The active title is reversed and marked active.

There is **no dual TX or automatic bridging**. Compose and `/msg` use only the
selected primary, including explicit node/channel targets. The implicit `/msg`
target remains the primary's last sender/channel; secondary MQTT arrivals do
not change it. Automatic AI replies instead use only the connection that
received the triggering message. A duplicate arriving over both links is
displayed once. If that packet is also seen on Serial, Bluetooth, or TCP, the
row is relabeled to that primary transport even when MQTT arrived first.
MQTT remains the label only when it is the sole observation. Automatic AI
replies still use the first owning connection, not the display label. Dedup
uses sender, packet ID, network/channel path, destination and payload (not
text alone), retaining at most 1000 packets for five minutes. No-ID packets
cannot be safely merged.

Each header ends with the sender's last known position. A valid fix is
`lat,lon >> https://maps.google.com/?q=lat,lon` on that same header. The pane
wraps on ` · `, and only at ` >> ` if the GPS field itself does not fit, so
the coordinate is not split. This is the compact Maps URL; a maps.app.goo.gl
code cannot be minted without a Google share request. Unknown, unset, or
out-of-range positions display `GPS N/A` and omit the URL. `0,0` is kept when
a real location source is present and omitted when the source is unset. The
value is the last position recorded for that sender, not a freshness guarantee.

MQTT TX uses `channel.<name>.from` when set, otherwise the connected radio's
node number, otherwise a node-shaped `mqtt.client_id`. It does not publish the
Meshtastic library default `!00000b0b` when one of those identities exists.
When that `from` value is not empty, the short name for that node is its last
four bytes, unless the same channel sets a non-empty `short_name`. Other
senders keep their own short names.

AI dispatch still requires the toggle, a private channel PSK, `ai_whitelist`,
and leading `@ai`. MQTT-origin shared-channel replies publish through that
MQTT connection only; radio-origin replies use that radio only. MQTT PKI DMs
remain unsupported: no AI DM dispatch, no radio fallback, and no plaintext or
legacy-PSK DM fallback. Closing/replacing the origin while AI is running leaves
its reply unsent. Host submission and local conversation display are not proof
of RF or peer delivery.

MQTT TX selects the resolved channel name explicitly as `channel_id` (for
example, `LongFast`); the Meshtastic encoder calculates its wire channel hash.
That name is not the radio's numeric slot or the legacy `channel_num` setting.
Multiple configured names may share a PSK without changing the reply channel.
Radio replies retain the received slot; an unnamed slot with an ambiguous PSK
needs an explicit `radio_index` mapping rather than choosing the first key.

AI conversations use durable `PWN::Sessions` transcripts scoped to the sender,
network/channel, private channel key and destination. Reconnecting or receiving
the same scope on another transport keeps that history; ordinary non-`@ai` RX
does not create an AI session. Session/runtime/provider errors are reported as
`AI failed`, separately from `TX failed` after a reply has been generated.
Broker EOF/protocol errors appear as bounded, generation-scoped UI notices;
they close the failed receiver without a Ruby thread crash dump. Use
`/transport` to open fresh subscriptions rather than replaying failed AI sends.

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
