# Plugin degradation and fallbacks

Each `PreflightChecker` health line links here. CI asserts every plugin in
`PLUGIN_DEPS` has an anchor and that documented fallbacks still exist.

## pwn-plugins-radare2

Required: `r2`. Fallback: `objdump` / `PWN::Plugins::REDB` binutils path.

## pwn-plugins-gdb

Required: `gdb`. Fallback: `PWN::Plugins::Debugger` still exposes `cyclic` helpers.

## pwn-plugins-nuclei

Required: `nuclei`. Fallback: `TransparentBrowser` + `pwn_eval`.

## pwn-plugins-sqlmap

Required: `sqlmap`. Fallback: `pwn_eval` HTTP clients.

## pwn-plugins-frida

Required: `frida`. Fallback: `Debugger` + `REDB`.

## pwn-plugins-aflplusplus

Required: `afl-fuzz`. Fallback: `PWN::Plugins::Fuzz.triage` on an existing crash dir.

## pwn-plugins-volatility

Required: `vol`. Fallback: `pwn_eval` + strings/REDB.

## pwn-plugins-nmapit

Required: `nmap`. Fallback: `Packet.tcp_connect_scan`.

## pwn-plugins-metasploit

Required: `msfconsole`. Fallback: `exploitdev`, `pwn_eval`, `PWN::Plugins::Handler`.

## pwn-plugins-burpsuite

Required: `burpsuite`. Fallback: `TransparentBrowser`, `nuclei`, `PWN::Plugins::MitmProxy`.

## pwn-plugins-zaproxy

Required: `zaproxy`. Fallback: `nuclei`, `TransparentBrowser`, `PWN::Plugins::MitmProxy`.

## pwn-plugins-packet

Required: `CAP_NET_RAW` **or** the capability broker helper. Install the helper
from `documentation/Capability-Broker-Sandbox.md` (setcap the helper binary, not
the Ruby interpreter). Fallback: `Packet.tcp_connect_scan` / `PWN::Plugins::Sock`.

## pwn-plugins-k8s

Required: `trivy` and docker.sock. Fallback: `sbom_scan` / `pwn_eval`.

## pwn-plugins-semgrep

Required: `semgrep`. Fallback: `sast` tools / `pwn_eval`.

## pwn-plugins-exploitdb

Required: `searchsploit`. Fallback: `intel_lookup`.

## pwn-plugins-recon

Required: `subfinder`, `httpx`. Fallback: `NmapIt.scan` + `Corpus.get`.

## pwn-plugins-credentialattack

Required: `hydra`, `john`, `hashcat`. Fallback: `pwn_eval` + `Corpus`.
