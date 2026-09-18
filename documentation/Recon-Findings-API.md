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

## Directed attack paths and combined impact

`enables: [finding_id]` is an outgoing edge: this finding enables the named
finding. Targets must already exist in the same engagement. For findings
recorded earlier, use `finding_record(op: 'link', id: ssrf_id,
enables: [admin_id])` or `Findings.link(id: ssrf_id, enables: [admin_id])`.
The update replaces outgoing `enables` links; legacy `attack_chain_refs` are
incoming prerequisites and remain supported. Missing IDs, duplicate edges,
self-links, cross-engagement links, and cycles are rejected.

Record the demonstrated combined impact with ordered source-to-impact `ids`:
`finding_record(op: 'chain_impact', ids: [ssrf_id, admin_id],
combined_impact_path: '/tmp/combined-impact.txt', escalate: true,
combined_severity: 'critical', severity_justification: justification,
reproduction_steps: steps)`. The evidence file must name each ID and describe
the combined impact; keep actual PoC output with it. This preserves a scoped
`chain_assessments` entry containing the ordered IDs, justification, steps,
and durable evidence hashes. Different paths retain separate assessments.

Reports enumerate directed root-to-leaf paths and rank them by the assessed
combined severity, not by summing or averaging constituent CVSS. An evidenced
SSRF → internal-admin takeover can therefore be one critical priority while
both constituent findings retain their medium CVSS in technical details.
HTML/Markdown display ranked paths before details; JSON includes `priorities`
and `attack_chains`; SARIF emits one result per path plus standalone findings.
Chain evidence is exported beside the report and verified against its hash.

An assessment applies only to its exact ordered path. Linking alone never
creates a critical rating: unassessed paths retain maximum constituent
severity and are explicitly marked `unassessed`. Severity is an evidence-based
assessment, not an automatically calculated chain CVSS score. The report
rejects invalid cyclic graphs and more than 1000 reportable paths rather than
silently dropping paths. Hash checks prove byte identity, not exploit execution.

## Verification boundaries

Specs use disposable localhost TCP/TLS fixtures and real nmap connect scans. Optional external scanner outputs are parser fixtures, not internet engagements. Context hook failures are visible; embeddings are never synthesized. No remote scanning is necessary to run these focused specs.
