# Installation

Tested primarily on Debian-based Linux (including Kali) and macOS using RVM-managed Ruby.

## Quick Install (Recommended)

```bash
$ cd /opt
$ sudo git clone https://github.com/0dayInc/pwn
$ cd /opt/pwn
$ ./install.sh
$ ./install.sh ruby-gem
$ pwn
pwn[v0.5.613]:001 >>> PWN.help
```

## Video Guide

[![Installing the pwn Security Automation Framework](https://raw.githubusercontent.com/0dayInc/pwn/master/documentation/pwn_install.png)](https://youtu.be/G7iLUY4FzsI)

## Ruby Gem Updates

```bash
$ rvm use ruby-4.0.5@pwn
$ gem uninstall --all --executables pwn
$ gem install --verbose pwn
```

For multi-user RVM use `rvmsudo` instead of `sudo` on gem commands.

## Upgrade Path (Ruby + PWN)

Use the vagrant provisioner or:

```bash
$ /opt/pwn/vagrant/provisioners/pwn.sh
```

This rebuilds the gemset when `.ruby-version` advances.

## Requirements

- Ruby (via RVM recommended)
- Git
- Build tools (for native extensions)
- Optional: Burp Suite Pro, Metasploit, etc. for full plugin capability

See the root [README.md](../README.md) and `install.sh` for latest details.

[[Diagrams]]
