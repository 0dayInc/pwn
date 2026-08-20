---
name: "att&ck"
description: "Exhaustively test each MITRE ATT&CK technique."
license: MIT
allowed-tools: [pwn, terminal, extrospection]
metadata:
  bundled: true
  references:
    - https://attack.mitre.org/
    - https://github.com/mitre-attack/attack-stix-data
    - ATT&CK 19.2
---

# ATT&CK exhaustive testing

Use when the ask names a technique (T1059, T1059.001), a tactic (TA0002),
ATT&CK coverage, purple-team emulation, or "test this like an adversary".
Pair with `capec` (how the attack is performed) and `cwe` (weakness proved).

## When to use

- "T1190", "OS Credential Dumping", "coverage of persistence"
- Red / purple team playbooks keyed to ATT&CK
- Mapping detections to techniques

## Methodologies

| Catalog | Role |
|---|---|
| ATT&CK 19.2 | techniques, sub-techniques, tactics (Enterprise / Mobile / ICS) |
| CAPEC (bundled `capec` skill) | attack-pattern execution for mapped IDs |
| CWE (bundled `cwe` skill) | weakness IDs after the procedure succeeds |
| NIST SP 800-115 | technical assessment wrapper |

## How to look up a technique

Each ATT&CK ID is a file in this skill:

```text
references/<id>.md
```

Examples: `references/T1059.md`, `references/T1059.001.md`,
`references/TA0006.md`. Open the file and follow it end-to-end.
`references/INDEX.md` lists every ID.

## Exhaustive catalog procedure

1. Identify platforms in scope (Windows, Linux, SaaS, ICS, Android, …).
2. Pick tactics in scope (or the whole matrix).
3. For every **applicable** technique, run `references/<id>.md`.
4. When sub-techniques exist, the parent is incomplete until every child is done.
5. Record N/A with a reason when the platform does not exist.
6. Findings cite the technique ID, not only the tactic.
7. Re-read saved evidence before calling the technique tested.

## Tooling

- Always: `skills_recall` this skill, then read the technique file.
- Then: `capec` and `cwe` for mapped IDs.
- Host: `pwn_eval`, shell, `PWN::Plugins::PS`.
- HTTP: `PWN::Plugins::BurpSuite` / `TransparentBrowser`.
- Network: `PWN::Plugins::Packet`.

## Pitfalls

- Tactics are groupings; they are not techniques.
- Atomic Tests / scanner mappings are inventory until you execute and save evidence.
- Skipping sub-techniques is not parent coverage.
- Detection engineering without an emulation attempt is not a test.

## Verification

A technique is done when its reference checklist is ticked and evidence
was re-read. Matrix coverage is done when every applicable technique
in the chosen tactics is tested or N/A.

## Catalog size (ATT&CK 19.2)

- Techniques / sub-techniques: 1166
- Tactics: 41

Full table: `references/INDEX.md`.
