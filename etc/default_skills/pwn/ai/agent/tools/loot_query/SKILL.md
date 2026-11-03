---
name: pwn-ai-agent-tools-lootquery
description: Query and capture encrypted engagement loot.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: false
  source: pwn/ai/agent/tools/loot_query.rb
---

# loot_query

Use the registered `loot_query` tool to query, store, ingest, or offer engagement
loot. This file registers a tool; it does not define a `Tools::LootQuery` module.

## How to call

Select `op: query` (the default) with `engagement`, `host`, `service`, `kind`, or
`finding_id` filters to obtain metadata without plaintext credentials. The Vault
query handler does not decrypt or open a device. Dispatch's separate output
redaction can require access to stored hardware secrets.

For `store` or `ingest`, pass `yubikey: {slot: 2, serial: "12345678", timeout: 30}`
only when hardware protection is intended. The slot must already be provisioned
for HMAC-SHA1. An empty selector chooses hardware defaults. The model-facing
schema allows only `slot`, `serial`, and `timeout`; never put a PIN, PUK, key,
password, or executable path in the selector. `offer` can use the same selector
when decrypting matching hardware loot.

## Pitfalls

- Missing hardware or failed touch raises; do not retry with software protection.
- Replacing an existing hardware label without a selector retains that backend.
- Treat `offer` results as secrets. Dispatch redacts array results before returning
  them; direct Ruby callers must not print or persist plaintext credentials.
- `VAULT_EXPANSION_FAILED` means Dispatch did not execute the handler.
  `VAULT_REDACTION_FAILED` with `handler_executed: true` means it already ran;
  reconcile effects before retrying.

## Verification

Use `PWN::AI::Agent::Registry.lookup(name: 'loot_query')` to inspect its schema
and handler after discovery. Offline tests stub only the device HMAC boundary,
use an isolated home, verify encrypted loot has no disk master key, and reject
selector executable overrides through Dispatch before any vault access.
