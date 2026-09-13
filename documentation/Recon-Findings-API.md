# Recon / Findings integration (P17 / P10)

## Parent integration hooks

- Existing autoloaded `PWN::Plugins::Recon` now exposes `run(opts)`; no new plugin autoload needed. New agent registration file: `lib/pwn/ai/agent/tools/recon_run.rb` (normal Registry discovery).
- `finding_record` handler uses `PWN::Plugins::Findings.record_structured(opts)`. The loop can treat `ArgumentError` as incomplete finding input; **do not infer a working PoC from accepted input**. No Loop/config/CLI changes in this patch.
- P3 hook: `Recon.run(..., ingest: true)` calls `PWN::AI::Context.ingest(path, session_id: engagement_id, **ingest_options)` after atomic persistence and JSON readback. `ingestor: callable` supports an alternate implementation with the same signature. Ingestion failure is returned in `result[:ingestion]` without discarding recon evidence. Preserve the literal asset ID in ingested chunks. Plugin callers opt in; the agent tool defaults ingestion on.

## Recon model

`Recon.run(target: '127.0.0.1', modules: %w[nmap banner tls], ports: [443], engagement_id: 'lab', ingest: true)`.

Single hostname/IP target (no arbitrary CLI switches, URL, CIDR, or shell command), explicit integer ports, per-operation timeout 15 seconds by default (maximum 300). `nmap` uses an unprivileged TCP connect scan, without sudo or NSE. Existing `NmapIt` API remains untouched. `banner` passively reads up to 4096 bytes; it does not send an HTTP request. `tls` collects the certificate with `trust_verified: false` (not a trust audit). Optional `subfinder` and `nuclei` run **only if explicitly named**, and unavailable tools return module status rather than fabricate results. Nuclei observations are not automatically promoted to findings.

Output: `{schema_version: 1, engagement_id:, assets: [{id:, address:, protocol:, port:, observations: [], evidence_paths: []}], modules: [], path:, ingestion: ...}`.

Stored at `~/.pwn/engagements/<engagement>/recon/assets.json`; `root:` overrides the engagements directory for isolated fixtures. Raw scan evidence is persisted beside it. IDs are `asset-` plus the first 24 hex SHA256 characters of lowercase address, protocol, port joined by `|`. Repeated same-identity observations merge across runs, not overwrite other assets. DNS names and resolved IPs are distinct identities unless the source explicitly supplies the same address; the pipeline does not silently infer aliases.

Use `affected_asset: asset[:id]` and `evidence_paths: asset[:evidence_paths]` in a structured finding. Stable IDs survive report generation and JSON ingestion unchanged.

## Strict findings boundary and compatibility

`record_structured` requires title, CWE identifier (`CWE-<positive integer>`), complete CVSS 3.0/3.1 base vector and matching numeric base score, affected_asset, nonempty existing readable absolute evidence_paths, nonempty PoC command/code string, attack_chain_refs array, remediation string, and numeric confidence 0..1. Chain refs must already exist in the same engagement. Invalid input raises before appending. CVSS 2/4, temporal/environmental vectors are explicitly unsupported (rejected, not normalized).

Legacy `Findings.record`, query/report, chain, render, and SARIF output remain callable; legacy record is not the strict API. Agent record and chain operations are strict. Existing query/export tool operations remain available. Accepted structured rows mark `verification_status: not_executed`; evidence hashes prove captured bytes, not exploit execution. Severity is derived from the validated score. No automatic escalation for linked findings.

`Findings.verify` / `finding_record op=verify` attests a working PoC from HTTP request/response files or a script execution log. The impact marker must appear in that evidence or the row stays `failed`. `Findings.retest` replays the same path after a fix (`still_open` vs `fixed`). `Findings.chain_impact` may raise combined severity only when a combined-impact file names every finding id. Issue work is unfinished while recorded findings remain `not_executed` (`issue_work_unverified`).

`PWN::AI::Agent::Swarm.ensure_specialists` / `agent_roster` writes recon, authz, injection, xss, and business_logic personas. SARIF export is `Findings.render`; `PWN::Plugins::Github.open_fix_pr` opens a remediation PR (tests stub the GitHub API).

Markdown/HTML/JSON report payloads compose connected explicit references into attack-chain sections, preserving all finding fields. Combined severity is maximum recorded constituent severity with a rationale explicitly disclaiming escalation and combined exploitability. This is not a computed CVSS chain score.

## Verification boundaries

Specs use disposable localhost TCP/TLS fixtures and real nmap connect scans. Optional external scanner outputs are parser fixtures, not internet engagements. Context hook failures are visible; embeddings are never synthesized. No remote scanning is necessary to run these focused specs.
