---
name: social-engineering
description: Plan and document social-engineering tests using OSSTMM human channel.
license: MIT
allowed-tools: [pwn, terminal]
metadata:
  bundled: true
  references:
    - https://www.isecom.org/research.html
    - https://attack.mitre.org/tactics/TA0001/
    - NIST-SP-800-115
---

# Social Engineering

Use when the ask is phishing, vishing, pretext, physical tailgating, or
a human-channel test. This is still a PWN procedure: write the scenario,
the artefacts, and the report. pwn-ai does not send mail or place calls
unless the operator's tools actually do that.

## When to use

- phishing / pretext campaign design
- OSSTMM human-channel assessment
- red-team initial access via people (`red-teaming` owns the ATT&CK wrap)

## Methodologies

| Catalog | Role |
|---|---|
| OSSTMM | human channel (and physical when paired with a building test) |
| MITRE ATT&CK | TA0001 Initial Access - T1566 phishing, T1598, T1656 |
| NIST SP 800-115 | social engineering as a technical assessment technique |
| PTES | pre-engagement rules and reporting |
| CREST / TIBER-EU | when the customer required a named SE code of practice |

## Tooling

- OSINT: `PWN::Plugins::Hunter`, `Github`, `Shodan`, `IPInfo`
- Mail / portal only if those plugins or WWW drivers are in the session
- Landing / payload hosting is out of band unless the operator named it
- Evidence: written pretext, target list, send log, report

## Procedure

1. Rules of the test: targets, forbidden people (exec assistants, on-call
   medical, etc. if the operator listed them), success definition.
2. OSINT for pretext (public bios, tech stack, current incidents).
3. Write one pretext + one landing or call script. Keep it specific.
4. Execute only through the channel the operator enabled. Log time,
   target, result (click / cred / report-to-SOC / ignore).
5. Stop at the objective (e.g. one valid session), then report.
6. Report: scenario, ATT&CK ids, metrics, recommended control (DMARC,
   reporting button, gate process).

## Pitfalls

- Do not invent a mass mailer. If there is no send tool, deliver the
  pack (pretext + list + landing copy) as the artefact.
- Do not target people the operator excluded.
- A witty email draft is not a completed SE test unless sending was
  out of scope.

## Verification

Rules note, pretext file, target list, and either a send/result log or
an explicit "pack only" deliverable that was written and read back.
