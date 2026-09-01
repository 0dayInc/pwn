---
name: pwn-plugins-k8s
description: Drive PWN::Plugins::K8s from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::K8s
  source: pwn/plugins/k8s.rb
---

# PWN::Plugins::K8s

trivy / kube-hunter wrappers plus docker-socket preflight.

## When to use

Call `PWN::Plugins::K8s` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/k8s.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::K8s.help
PWN::Plugins::K8s.required_bins(opts)
```

## Public methods

- `required_bins`
- `trivy`
- `kube_hunter`
- `docker_socket`
- `authors`
- `help`
- `docker_socket?`

## Source

`pwn/plugins/k8s.rb`

## Verification

`PWN::Plugins::K8s.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
