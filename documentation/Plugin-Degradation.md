# Plugin degradation and fallbacks

Each `PreflightChecker` health line links here. CI asserts every plugin in
`PLUGIN_DEPS` has an anchor and that documented fallbacks still exist.

## pwn-plugins-radare2

Required: `r2`. Fallback: `objdump` / `PWN::Plugins::REDB` binutils path.

## pwn-plugins-gdb

Required: `gdb`. Fallback: `PWN::Plugins::Debugger` still exposes `cyclic` helpers.

## pwn-plugins-nuclei

Required: `nuclei`. Fallback: `TransparentBrowser` + `pwn_eval`.

## pwn-plugins-httpx

Required: `httpx`. Fallback: `TransparentBrowser` + `NmapIt.scan`.

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

Required: `burpsuite`. Fallback: `TransparentBrowser`, `nuclei`, `httpx`, `PWN::Plugins::MitmProxy`.

## pwn-plugins-zaproxy

Required: `zaproxy`. Fallback: `nuclei`, `httpx`, `TransparentBrowser`, `PWN::Plugins::MitmProxy`.

## pwn-plugins-packet

Required: `CAP_NET_RAW` **or** the capability broker helper. Install the helper
from [Capability-Broker-Sandbox](Capability-Broker-Sandbox.md) using its dedicated
service capability boundary. Do not setcap the Ruby interpreter or Ruby script
(Linux ignores script file capabilities). Fallback: `Packet.tcp_connect_scan` /
`PWN::Plugins::Sock`.

## pwn-plugins-k8s

Required: `trivy` and docker.sock. Fallback: `sbom_scan` / `pwn_eval`.

## pwn-plugins-semgrep

Required: `semgrep`. Fallback: `sast` tools / `pwn_eval`.

## pwn-plugins-exploitdb

Required: `searchsploit`. Fallback: `intel_lookup`.

## pwn-plugins-recon

Required: `subfinder`, `httpx`. Fallback: `NmapIt.scan` + `Corpus.get`.

## pwn-plugins-yubikey

Required: none. `required_bins` is empty. Preflight probes HIDAPI and PC/SC
through `available?` and reports `FIDO native transport` or
`PC/SC native transport` when a library is missing. It never opens a device,
requests a PIN, or performs a challenge. An `ok` library probe does not
establish device availability, provisioning, or authorization.
Hardware-backed vault operations require the selected YubiKey and its existing
HMAC-SHA1 OTP slot; missing devices, denied touch, or authentication failures
raise without falling back to a disk master key or software MFA. Restore device
access before retrying. Dispatch blocks the handler when vault expansion fails;
if output redaction fails after execution, it withholds the result and reports
that the handler executed, so verify its effects before retrying.

## pwn-plugins-credentialattack

Required: `hydra`, `john`, `hashcat`. Fallback: `pwn_eval` + `Corpus`.
