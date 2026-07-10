# Troubleshooting

## "Which capabilities are broken on this host?"

Run the built-in doctor — it tells you exactly which native gem or external
binary is missing, what OS package provides it, and which `PWN::` constants
are degraded as a result:

```bash
$ pwn setup            # or: pwn_setup / pwn --setup
```

Then fix a subset:

```bash
$ pwn setup --profile web        # or: net · sdr · vision · voice · db · hardware · exploit · full
$ pwn setup --deps --dry-run     # show the apt/dnf/pacman/brew/port commands without running them
```

See [Installation](Installation.md#pwn-setup--the-post-install-doctor--provisioner)
for the full profile table and `PWN::Setup` API.

## `LoadError` / `cannot load such file -- pg` (or rmagick, pcaprub, …)

A native extension failed to compile because its OS headers weren't present
at `gem install` time. `pwn setup` knows the mapping for every package
manager and will install the headers **and** rebuild the gem:

```bash
$ pwn setup --profile db      # pg / sqlite3
$ pwn setup --profile vision  # rmagick / rtesseract / oily_png / gruff
$ pwn setup --profile net     # pcaprub
```

The runtime is `autoload`ed, so a missing extension only surfaces when you
touch the constant that needs it — the rest of PWN keeps working.

## `nmap` / `chromium` / `gqrx` / … not found on `$PATH`

Same fix — `PWN::Setup::TOOLCHAIN` maps every wrapped binary to its OS
package on `apt` / `dnf` / `pacman` / `brew` / `port`:

```bash
$ pwn setup --profile web     # chromium · geckodriver · burpsuite · zaproxy · sqlmap · tor
$ pwn setup --profile sdr     # gqrx · rtl_sdr · hackrf_info · SoapySDRUtil · multimon-ng · sox
```

## SHIFT+ENTER submits instead of newline

`pwn-ai` / `pwn-asm` need the terminal to send a *distinct* code for
Shift-Enter. Under **tmux** both sides must be configured:

```tmux
# ~/.tmux.conf
set -s  extended-keys on
set -as terminal-features 'xterm*:extkeys'   # replace xterm* with your $TERM
```

Then fully **detach and re-attach** (a `source-file` isn't enough for
`terminal-features`). Verify with `tmux display -p '#{client_termfeatures}'`
— it must include `extkeys`.

## `502 Bad Gateway` from a proxy plugin

The upstream (Burp/ZAP) isn't listening. Check:

```bash
ps aux | grep -E 'burp|zap'
ss -tlnp | grep -E ':8080|:1337'
```

Restart via `PWN::Plugins::BurpSuite.start` / `PWN::Plugins::Zaproxy.start` or
fix the port via `pwn-vault` (`~/.pwn/pwn.yaml`).

## `Psych::DisallowedClass` on cron/agents YAML

Fixed in current `PWN::Cron` / `Swarm` — both loaders now pass
`permitted_classes: [Symbol]`. If you see it, `gem update pwn`.

## Agent stops early ("max iterations")

Raise `ai.agent.max_iters` in `~/.pwn/pwn.yaml` (edit via `pwn-vault`), or
split the request.

## A tool is stuck at 0 % success

If you've since fixed the tool, wipe the stale telemetry so it stops steering
the agent away: `metrics_reset(confirm: true)`.

## LLM auth

| Engine | Fix |
|---|---|
| grok `oauth: true` | first run prints a `https://accounts.x.ai/…` URL — open it, approve, token is cached |
| ollama | ensure `ollama serve` is running and `base_uri:` matches |
| others | check `key:` under `ai.<engine>` in `~/.pwn/pwn.yaml` (edit via `pwn-vault`) |

`pwn setup` reports the `AI engine` row as `MISSING` until a key is set.

## Diagrams won't rebuild

```bash
$ pwn setup --profile vision   # installs graphviz (dot)
$ cd documentation/diagrams && ./build.sh
```

## `No supported package manager found`

`PWN::Setup` supports `apt-get`, `dnf`, `pacman`, `brew`, and `port`. On other
systems use `pwn setup --dry-run --profile <name>` to print the package
list, then install equivalents by hand.

[← Home](Home.md)
