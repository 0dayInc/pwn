# `PWN::Plugins::Metasploit`

RPC client for `msfrpcd` - search modules, set options, run exploits, interact
with sessions, all from Ruby.

> **Install:** `pwn setup --profile exploit` - metasploit-framework ·
> sqlmap. See [Installation](Installation.md).

## Configure

`connect(yaml_conf:)` reads a separate operator-owned YAML file, not the
`metasploit:` block in the encrypted PWN vault. Required keys are
`msfrpcd_host`, `port`, `username`, and `password`. Keep that file private and
use only a trusted local daemon or protected transport. Without `yaml_conf`,
the legacy provider file is resolved using `PWN_ROOT` and `PWN_PROVIDER`.
Review `msfrpcd --help` for daemon transport/authentication settings; no daemon
or credential enrollment is performed by this documentation check.

## Use

```ruby
console = PWN::Plugins::Metasploit.connect(yaml_conf: '/path/to/metasploit.yaml')
PWN::Plugins::Metasploit.console_exec(console_obj: console, cmd: 'search jenkins')
# Further commands use the same console_exec interface; inspect results before
# executing a module. This example does not launch an exploit.
PWN::Plugins::Metasploit.disconnect(console_obj: console)
```

CLI: `pwn_msf_postgres_login /path/to/private-msfrpcd.yaml 10.0.0.5 5432`

[← Home](Home.md) · [Plugins](Plugins.md)
