---
name: sast-code-scans
description: Run PWN::SAST on a tree, report findings, and optionally file tickets.
license: MIT
allowed-tools: [pwn, terminal]
metadata:
  bundled: true
  references:
    - CWE-78
    - CWE-89
    - CWE-502
    - CWE-798
---

# SAST Code Scans

Use when the ask is to scan source, add a rule, or push SAST results to
DefectDojo / Jira. Reading the rule list is not a scan.

## When to use

- `pwn_sast` / `PWN::SAST::Factory.start`
- "scan this repo for secrets / SQLi / command exec"
- write or extend a `PWN::SAST::*` rule

## Methodologies

- OWASP ASVS (verify) and WSTG (when the sink is web)
- CWE (rule IDs on every finding)
- NIST SP 800-115: static analysis as one technical assessment technique
- OWASP MASVS / MSTG when the tree is a mobile app

## Tooling

- Engine: `PWN::SAST::Factory.start(dir_path:)` or CLI `pwn_sast -d DIR -o OUT`.
- Families (48 modules): command exec (Java/Python/Ruby/Go/Scala/Shell/Sudo),
  web/DOM (CSRF, innerHTML, postMessage, localStorage), injection (SQL,
  Eval, Log4J, PHP/TS type juggling, Java deserial), crypto/secrets (MD5,
  SSL, PrivateKey, Token, Password, HTTPAuthorizationHeader), memory
  (`BannedFunctionCallsC`, `UseAfterFree`), infra (AWS, AMQP guest, POM).
- Report: `PWN::Reports::SAST.generate(dir_path:, results_hash:, output_dir:)`.
- Tickets: `PWN::Plugins::DefectDojo.importscan`, `PWN::Plugins::JiraDataCenter`.

## Procedure

1. Resolve `dir_path` (repo root or the path in the ask). `ls` once, then
   scan.
2. Run Factory or `pwn_sast`. Capture the results hash / output dir.
3. Read the report (HTML/JSON). Summarize by CWE and severity. Do not
   claim "clean" from an empty `ls`.
4. If asked to file, import the JSON/HTML into DefectDojo or Jira.
5. New rule: copy an existing `lib/pwn/sast/*.rb`, implement
   `self.scan(opts = {})` returning `{file:, line:, match:, cwe:, severity:}`,
   then re-run Factory on a fixture.

## Pitfalls

- `bundle exec rake` green is verify of *this* gem, not a SAST of the
  target tree.
- A README dump is not `pwn_sast` output.
- After writing a report file, read it back before the final.

## Verification

`output_dir` exists with HTML/JSON (or the results hash is non-nil) and
the answer cites counts or concrete findings from that artefact.
