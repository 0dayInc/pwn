# Installation

PWN is tested on **Debian-based Linux** (Kali, Ubuntu) and **macOS**, using
Ruby via **RVM**.

## Quick install (recommended)

```bash
cd /opt
sudo git clone https://github.com/0dayinc/pwn
cd /opt/pwn
./install.sh          # system deps (nmap, chromium, graphviz, …)
./install.sh ruby-gem # rvm gemset + bundle install + rake install
pwn                   # launch the REPL
```

```text
pwn[v0.5.616]:001 >>> PWN.help
```

## Gem-only install

```bash
rvm install ruby-4.0.5
rvm use     ruby-4.0.5@pwn --create
gem install --verbose pwn
pwn
```

## Upgrading

```bash
rvm use ruby-4.0.5@pwn
gem uninstall --all --executables pwn
gem install --verbose pwn
```

or from a checkout:

```bash
cd /opt/pwn && git pull && rvmsudo rake install
```

## First-run configuration

`pwn` creates `~/.pwn/` on first launch. Add at least one LLM engine to
`~/.pwn/config.yml` to enable `pwn-ai` — see [Configuration](Configuration.md).

## Optional external tools

PWN wraps these when present on `$PATH`; none are hard requirements:

| Tool | Used by |
|---|---|
| `nmap` | `PWN::Plugins::NmapIt` |
| Burp Suite Pro (+ REST API) | `PWN::Plugins::BurpSuite` |
| `msfconsole` / msfrpcd | `PWN::Plugins::Metasploit` |
| `chromium` / `google-chrome` | `PWN::Plugins::TransparentBrowser` |
| `zaproxy` | `PWN::Plugins::Zaproxy` (fallback) |
| `gqrx` | `PWN::SDR::GQRX` |
| `adb` | `PWN::Plugins::Android` |
| `graphviz` (`dot`) | rebuilding these diagrams |
| `tor` | `PWN::Plugins::Tor` |

## Verify

```ruby
pwn[v0.5.616]:001 >>> PWN::Plugins.constants.count   # => 66
pwn[v0.5.616]:002 >>> PWN::SAST.constants.count      # => 48
pwn[v0.5.616]:003 >>> pwn-ai                         # launches agent TUI
```

**Next:** [Configuration](Configuration.md) · [General Usage](General-PWN-Usage.md)

[← Home](Home.md)
