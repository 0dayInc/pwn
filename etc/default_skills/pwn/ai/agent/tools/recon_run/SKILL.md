---
name: pwn-ai-agent-tools-reconrun
description: Run recon pipelines with optional hardware-protected loot.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Ai::Agent::Tools::ReconRun
  source: pwn/ai/agent/tools/recon_run.rb
---

# recon_run registry tool

Use the registered `recon_run` tool or `PWN::Plugins::Recon.run`; this file
registers a tool, not a Ruby class named `PWN::Ai::Agent::Tools::ReconRun`.

## When to use

Run selected recon modules against a single authorized target and persist their
asset/evidence model. Scanner observations are not proven findings.

## Methodologies

Supply `target` and a nonempty `modules` array from `nmap`, `banner`, `tls`,
`subfinder`, `nuclei`. Optional `ports`, `engagement_id`, positive `timeout` up to
300 seconds and `ingest` control the pipeline; tool ingestion defaults to true.

## How to call

```json
{"target":"app.example.test","modules":["banner"],"ports":[443],"ingest":false,"yubikey":{"slot":2}}
```

## Hardware protection

The optional `yubikey` selector accepts only integer `slot` 1/2, decimal String
`serial`, and positive `timeout` seconds. An empty object chooses hardware
defaults. It forwards into Vault ingestion without provisioning or software
fallback. Device access errors remain failures. PINs, seeds, arbitrary executable
paths and secret selector fields are forbidden by the tool schema.

Only harvested loot is hardware encrypted. Raw scanner evidence and the asset
model remain ordinary files; protect those separately. Do not claim a completed
scan when harvesting failed, or replay an expensive scan blindly after device loss.

## Source

`pwn/ai/agent/tools/recon_run.rb`

## Verification

Run `spec/lib/pwn/ai/agent/tools/recon_run_spec.rb` and
`spec/lib/pwn/ai/agent/tools/recon_run_yubikey_spec.rb`. The latter exercises the
real handler/Recon/Vault path with fake socket/device boundaries and no live scan.
