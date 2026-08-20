---
name: cwe
description: Exhaustively test a target against every applicable CWE.
license: MIT
allowed-tools: [pwn, terminal, extrospection]
metadata:
  bundled: true
  references:
    - https://cwe.mitre.org/
    - https://cwe.mitre.org/data/downloads.html
    - CWE List 4.20
---

# CWE exhaustive testing

Use when the ask names a CWE, OWASP/WSTG mapping to CWE, a CVE that
maps to CWE, SAST output with CWE IDs, or "test this app/binary/firmware
against CWE". Pair with `sast-code-scans` when source exists and
`web-application-penetration-testing` when the surface is HTTP.

## When to use

- "CWE-79", "test for SQLi", "map findings to CWE"
- CVE analysis that must name the underlying weakness
- Coverage pass: every CWE that applies to this stack

## Methodologies

| Catalog | Role |
|---|---|
| CWE List 4.20 | weakness IDs, views, categories — source of each reference |
| OWASP WSTG / ASVS | web mapping onto CWE IDs |
| NIST SP 800-115 | technical assessment techniques wrapping these tests |
| ATT&CK / CAPEC | attacker technique; still report the CWE |

## How to look up a CWE

Each CWE number is a file in this skill:

```text
references/CWE-<id>.md
```

Examples: `references/CWE-79.md`, `references/CWE-89.md`,
`references/CWE-787.md`. Open that file and follow its procedure
end-to-end. Do not improvise a one-line "XSS test" when the reference
exists. `references/INDEX.md` lists every ID.

## Exhaustive catalog procedure

1. Identify the target class (web, API, native, firmware, cloud, human).
2. Pick a CWE view (CWE-1000 Research Concepts, CWE-699 Software Development,
   CWE-1194 Hardware Design, CWE-1326 CWE Top 25, etc.) from `references/`.
3. For every **applicable** member, run `references/CWE-<id>.md`.
4. Record N/A with a reason when the platform does not exist.
5. Findings cite the member CWE, not only the view/category.
6. Re-read saved evidence before calling the CWE tested.

## Tooling

- Always: `skills_recall` this skill, then read the CWE reference file.
- HTTP: `PWN::Plugins::BurpSuite` or `TransparentBrowser`.
- Source: `PWN::SAST::Factory.start` / `pwn_sast`.
- Authz: `PWN::Bounty::LifecycleAuthzReplay`.
- Native: `PWN::Plugins::Assembly`, gdb via shell.
- Hardware: `PWN::Plugins::Serial`, BusPirate.

## Pitfalls

- Scanner output is inventory, not a test.
- Categories and views are groupings; they are not vulnerabilities.
- One payload on one parameter is not exhaustive for a Base CWE.
- Do not skip deprecated IDs without following the replacement.

## Verification

A CWE is done when its reference checklist is ticked and evidence
paths were re-read. The engagement is CWE-complete when every
applicable ID in the chosen view is tested or N/A.

## Catalog size (CWE 4.20)

- Weaknesses: 969
- Categories: 422
- Views: 59

Full table: `references/INDEX.md`.
