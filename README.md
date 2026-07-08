![PWN](https://raw.githubusercontent.com/0dayInc/pwn/master/documentation/PWN.png)

### **Table of Contents** ###

- [Intro](#intro)
  * [What is PWN](#what-is-pwn)
  * [Why PWN](#why-pwn)
  * [How PWN Works](#how-pwn-works)
- [Documentation](#documentation)
- [Installation](#installation)
- [General Usage](#general-usage)
- [Call to Arms](#call-to-arms)
- [Module Documentation](#module-documentation)
- [Keep Us Caffeinated](#keep-us-caffeinated)
- [0x004D65726368](#0x004d65726368)

---

### **Intro** ###

#### **What is PWN** ####

PWN (pronounced /pōn/ — *pone*) is an open-source **offensive-security
automation framework** and **continuous-security-integration** platform.
It gives security researchers, red teamers, penetration testers and
vulnerability researchers a single, scriptable Ruby surface over the entire
offensive toolchain — from OSINT and network discovery, through web / cloud /
hardware / radio exploitation, to reporting and disclosure — and puts a
**self-improving, tool-calling, multi-agent AI** on top of it.

**In numbers:** 66 `PWN::Plugins` · 48 `PWN::SAST` rules · 90 `PWN::AWS`
service wrappers · 21 `PWN::WWW` site drivers · 52 `bin/pwn_*` CLI drivers ·
5 LLM engines · 10 agent toolsets · 45+ LLM-callable tools.

Full page: [What is PWN](documentation/What-is-PWN.md)

#### **Why PWN** ####

Offensive security is a *toolchain problem*. PWN's bet is that the right
abstraction is **plain Ruby methods with a uniform `opts = {}` signature**,
exposed simultaneously to a human in a REPL, an LLM in a tool-calling loop, a
shell script in CI, and a cron job at 3 am — all open-source and auditable,
which matters when the caller is autonomous.

Full page: [Why PWN](documentation/Why-PWN.md)

#### **How PWN Works** ####

Five layers, edges only ever go down:

![PWN Overall Architecture](documentation/diagrams/overall-pwn-architecture.svg)

The AI layer closes a **self-improvement loop** on every turn — Metrics +
Learning + **Mistakes** (introspection / negative feedback) joined with
Snapshot + Drift + Intel + RF (extrospection) via `extro_correlate`, so the
agent knows whether a failure was *its* fault or *the world* changed —
**and does not repeat the same mistake twice**:

![pwn-ai Feedback Learning Loop](documentation/diagrams/pwn-ai-feedback-learning-loop.svg)

Failures are fingerprinted cross-session (`~/.pwn/mistakes.json`), tagged
`[REPEATING]` / `[REGRESSED]`, and their **fix** is handed straight back inline
on the next recurrence:

![Mistakes Negative-Feedback Loop](documentation/diagrams/mistakes-negative-feedback.svg)

And **Swarm** runs multiple personas — each a full tool-calling agent,
optionally on a *different* LLM engine — over a shared append-only bus:

![Swarm Multi-Agent](documentation/diagrams/swarm-multi-agent.svg)

Full pages: [How PWN Works](documentation/How-PWN-Works.md) ·
[All 27 Data-Flow Diagrams](documentation/Diagrams.md)

---

### **Documentation** ###

The complete wiki lives in this repo at **[`documentation/Home.md`](documentation/Home.md)**.

| Start Here | Entry Points | AI Subsystem | Capabilities |
|---|---|---|---|
| [What is PWN](documentation/What-is-PWN.md) | [`pwn` REPL](documentation/pwn-REPL.md) | [AI / LLM Integration](documentation/AI-Integration.md) | [Plugins (66)](documentation/Plugins.md) |
| [Why PWN](documentation/Why-PWN.md) | [`pwn-ai` Agent](documentation/pwn-ai-Agent.md) | [Agent Tool Registry](documentation/Agent-Tool-Registry.md) | [SAST (48)](documentation/SAST.md) |
| [How PWN Works](documentation/How-PWN-Works.md) | [CLI Drivers (52)](documentation/CLI-Drivers.md) | [Memory · Skills · Learning](documentation/Skills-Memory-Learning.md) | [AWS (90)](documentation/AWS.md) |
| [Installation](documentation/Installation.md) | [Build a Driver](documentation/Drivers.md) | [Mistakes (neg-feedback)](documentation/Mistakes.md) | [WWW (21)](documentation/WWW.md) |
| [General Usage](documentation/General-PWN-Usage.md) | | [Extrospection](documentation/Extrospection.md) | [SDR / Radio](documentation/SDR.md) |
| [Configuration](documentation/Configuration.md) | | [Swarm (multi-agent)](documentation/Swarm.md) | [Hardware](documentation/Hardware.md) |
| [Configuration](documentation/Configuration.md) | | [Sessions](documentation/Sessions.md) · [Cron](documentation/Cron.md) | [Reports](documentation/Reporting.md) |
| [`~/.pwn/` Persistence](documentation/Persistence.md) | | | [BurpSuite](documentation/BurpSuite.md) · [NmapIt](documentation/NmapIt.md) |
| **[All Diagrams](documentation/Diagrams.md)** | | | [Metasploit](documentation/Metasploit.md) · [Fuzzing](documentation/Fuzzing.md) |
| [Troubleshooting](documentation/Troubleshooting.md) | | | [Hardware](documentation/Hardware.md) · [Blockchain](documentation/Blockchain.md) |
| [Contributing](documentation/Contributing.md) | | | [Bounty](documentation/Bounty.md) · [FFI](documentation/FFI.md) · [Banner](documentation/Banner.md) |

Rebuild every SVG from its Graphviz source:
`cd documentation/diagrams && ./build.sh`

---

### **Installation** ###

Tested on Debian-based Linux & macOS, Ruby via RVM.

```
$ cd /opt
$ sudo git clone https://github.com/0dayinc/pwn
$ cd /opt/pwn
$ ./install.sh
$ ./install.sh ruby-gem
$ pwn
pwn[v0.5.616]:001 >>> PWN.help
```

[![Installing the pwn Security Automation Framework](https://raw.githubusercontent.com/0dayInc/pwn/master/documentation/pwn_install.png)](https://youtu.be/G7iLUY4FzsI)

Full page: [Installation](documentation/Installation.md) ·
[Configuration](documentation/Configuration.md)

---

### **General Usage** ###

[General Usage Quick-Start](https://github.com/0dayinc/pwn/wiki/General-PWN-Usage) ·
local: [General PWN Usage](documentation/General-PWN-Usage.md)

Update PWN frequently — new plugins, agent tools, skills and zero-day tooling
land regularly:

```
$ rvm list gemsets
$ rvm use ruby-4.0.5@pwn
$ gem uninstall --all --executables pwn
$ gem install --verbose pwn
$ pwn
pwn[v0.5.616]:001 >>> PWN.help
```

If using a multi-user RVM install:

```
$ rvm use ruby-4.0.5@pwn
$ rvmsudo gem uninstall --all --executables pwn
$ rvmsudo gem install --verbose pwn
```

**Inside the `pwn` REPL:**
- Full access to every `PWN::` module.
- `pwn-ai` — launch the autonomous agent TUI (SHIFT+ENTER newline, ENTER submit).
- `pwn-asm`, `pwn-ai-memory`, `pwn-ai-sessions`, `pwn-ai-cron`, `pwn-ai-delegate`.

**Headless / CI one-shot (`pwn --ai`):**

```
$ pwn --ai 'What ports are listening on this host?'
$ echo "$LONG_PROMPT" | pwn --ai -
$ pwn -Y ./ci/pwn.yaml --ai 'Run pwn_sast against ./src and summarise HIGH findings' > findings.txt
```

PWN periodically upgrades to the latest Ruby (`/opt/pwn/.ruby-version`).
Easiest upgrade of Ruby + pwn from a previous install:

```
$ /opt/pwn/vagrant/provisioners/pwn.sh
```

---

### **Call to Arms** ###

Contributions that expand PWN's offensive capabilities are welcome. If you can
provide access to additional commercial LLMs, security scanners, or bounty
platforms — or wish to contribute plugins, AI skills, or exploit modules —
please [email us](mailto:support@0dayinc.com). See
[CONTRIBUTING.md](https://github.com/0dayInc/pwn/blob/master/CONTRIBUTING.md)
and the local [Contributing](documentation/Contributing.md) page.

---

### **Module Documentation** ###

**Primary:** [`documentation/Home.md`](documentation/Home.md) — the full local
wiki with 30+ pages and 26 SVG data-flow diagrams.

**API reference:** [rubydoc.info/gems/pwn](https://www.rubydoc.info/gems/pwn),
or in-REPL: `PWN::Plugins::BurpSuite.help`, `show-source`, `ls`.

Highlights:
[Plugins](documentation/Plugins.md) ·
[BurpSuite](documentation/BurpSuite.md) ·
[Transparent-Browser](documentation/Transparent-Browser.md) ·
[pwn-ai Agent](documentation/pwn-ai-Agent.md) ·
[Swarm](documentation/Swarm.md) ·
[Extrospection](documentation/Extrospection.md) ·
[SAST](documentation/SAST.md) ·
[AI Integration](documentation/AI-Integration.md)

I hope you enjoy PWN — and remember: **always have permission** before any
security testing. Now go pwn all the things (responsibly)!

---

### **Keep Us Caffeinated** ###
If you've found this project useful and you're interested in supporting our efforts, we invite you to take a brief moment to keep us caffeinated:

[![Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoff.ee/0dayinc)


### [**0x004D65726368**](https://0day.myspreadshop.com/) ###

[![PWN Sticker](https://image.spreadshirtmedia.com/image-server/v1/products/T1459A839PA3861PT28D1044068794FS8193/views/1,width=300,height=300,appearanceId=839,backgroundColor=000000/ultimate-hacker-t-shirt-to-convey-to-the-public-a-hackers-favorite-past-time.jpg)](https://0day.myspreadshop.com/stickers)

[![Coffee Mug](https://image.spreadshirtmedia.com/image-server/v1/products/T1313A1PA3933PT10X2Y25D1020472680FS6327/views/3,width=300,height=300,appearanceId=1,backgroundColor=000000/https0dayinccom.jpg)](https://0day.myspreadshop.com/accessories+mugs+%26+drinkware)

[![Mouse Pad](https://image.spreadshirtmedia.com/image-server/v1/products/T993A1PA2168PT10X162Y26D1044068794S100/views/1,width=300,height=300,appearanceId=1,backgroundColor=000000/ultimate-hacker-t-shirt-to-convey-to-the-public-a-hackers-favorite-past-time.jpg)](https://0day.myspreadshop.com/accessories)

[![0day Inc.](https://image.spreadshirtmedia.com/image-server/v1/products/T951A550PA3076PT17X0Y73D1020472680FS8515/views/1,width=300,height=300,appearanceId=70,backgroundColor=000000/https0dayinccom.jpg)](https://shop.spreadshirt.com/0day/0dayinc-A5c3e498cf937643162a01b5f?productType=951&appearance=70)

[![Black Fingerprint Hoodie](https://image.spreadshirtmedia.com/image-server/v1/products/T111A2PA3208PT17X169Y51D1020472728FS6268/views/1,width=300,height=300,appearanceId=2/https0dayinccom.jpg)](https://shop.spreadshirt.com/0day/blackfingerprint-A5c3e49db1cbf3a0b9596b4d0?productType=111&appearance=2)
