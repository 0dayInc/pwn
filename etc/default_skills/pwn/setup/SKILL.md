---
name: pwn-setup
description: Drive PWN::Setup from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Setup
  source: pwn/setup.rb
---

# PWN::Setup

PWN::Setup — post-install "doctor" and capability provisioner. PWN ships as a **single gem** whose runtime is 100 % `autoload`ed (`lib/pwn.rb`) — a plugin whose native gem or OS binary is missing costs nothing until you touch that constant. `PWN::Setup` is the piece that grows a bare `gem install pwn` into a fully-armed host **after** the gem is installed, instead of **before** via a chain of bash scripts that assume `/opt/pwn`, `rvmsudo`, `screen`, and MacPorts. It is the Ruby-native, versioned-with-the-gem replacement for the `case $os` blocks previously buried in `install.sh` and `packer/provisioners/pwn.sh`. pwn setup # doctor (read-only) pwn setup --check # same pwn setup --deps # install OS headers for EVERY native gem pwn setup --profile web # install just what TransparentBrowser/Burp need pwn setup --profile sdr --yes # non-interactive pwn setup --list-profiles Also exposed as `pwn_setup` (driver) and `pwn --setup[=PROFILE]`.

## When to use

Call `PWN::Setup` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/setup.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Setup.help
PWN::Setup.pkg_manager(opts)
```

## Public methods

- `pkg_manager`
- `check`
- `deps`
- `terminal`
- `list_profiles`
- `migrate`
- `ensure_cron`
- `authors`
- `help`

## Source

`pwn/setup.rb`

## Verification

`PWN::Setup.respond_to?(:pkg_manager)` after the
module is loaded. Read the source for parameter names.
