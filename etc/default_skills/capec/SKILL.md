---
name: capec
description: Exhaustively execute every applicable CAPEC attack pattern.
license: MIT
allowed-tools: [pwn, terminal, extrospection]
metadata:
  bundled: true
  references:
    - https://capec.mitre.org/
    - https://capec.mitre.org/data/downloads.html
    - CAPEC List 3.9
---

# CAPEC exhaustive testing

Use when the ask names a CAPEC ID, an ATT&CK technique that maps to
CAPEC, or "execute this attack pattern". Pair with the `cwe` skill:
CAPEC is how the attack is performed; CWE is the weakness you prove.

## When to use

- "CAPEC-66", "attack pattern", "how would an attacker XSS this"
- Purple-team / red-team playbooks that need a numbered flow
- Coverage pass: every CAPEC that applies to this stack

## Methodologies

| Catalog | Role |
|---|---|
| CAPEC List 3.9 | attack pattern IDs, views, categories |
| CWE (bundled `cwe` skill) | weakness IDs related to each pattern |
| ATT&CK | adversary technique mapping when present |
| OWASP WSTG | web execution of HTTP-related patterns |

## How to look up a CAPEC

Each CAPEC number is a file in this skill:

```text
references/CAPEC-<id>.md
```

Examples: `references/CAPEC-66.md`, `references/CAPEC-1.md`.
Open that file and follow its procedure end-to-end, including every
related CWE via `../cwe/references/CWE-<id>.md`. `references/INDEX.md`
lists every ID.

## Exhaustive catalog procedure

1. Identify the target class (web, API, native, firmware, human, network).
2. Pick a CAPEC view (CAPEC-1000 Mechanisms of Attack, etc.).
3. For every **applicable** member, run `references/CAPEC-<id>.md`.
4. Record N/A with a reason when prerequisites cannot be met.
5. Findings cite the member CAPEC **and** related CWE IDs.
6. Re-read saved evidence before calling the pattern tested.

## Tooling

- Always: `skills_recall` this skill, then read the CAPEC reference.
- Then: `skills_recall` `cwe` for related weakness procedures.
- HTTP: `PWN::Plugins::BurpSuite` or `TransparentBrowser`.
- Source: `PWN::SAST::Factory.start` / `pwn_sast`.
- Authz: `PWN::Bounty::LifecycleAuthzReplay`.

## Pitfalls

- Categories and views are groupings; they are not attacks.
- Skipping the related CWE procedure leaves the weakness unproven.
- One blocked payload is not an exhaustive CAPEC test.
- Do not skip deprecated IDs without following the replacement.

## Verification

A CAPEC is done when its reference checklist is ticked, related CWE
files were run, and evidence paths were re-read.

## Catalog size (CAPEC 3.9)

- Attack patterns: 615
- Categories: 78
- Views: 13

Full table: `references/INDEX.md`.
