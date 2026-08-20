# CAPEC-681: Exploitation of Improperly Controlled Hardware Security Identifiers

- Catalog: [CAPEC-681](https://capec.mitre.org/data/definitions/681.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary takes advantage of missing or incorrectly configured security identifiers (e.g., tokens), which are used for access control within a System-on-Chip (SoC), to read/write data or execute a given action.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-681 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-681 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-681`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- Awareness of the hardware being leveraged.
- Access to the hardware being leveraged.

## Skills required

- Medium: Ability to execute actions within the SoC.
- High: Intricate knowledge of the identifiers being utilized.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Review generation of security identifiers for design inconsistencies and common weaknesses.
- Review security identifier decoders for design inconsistencies and common weaknesses.
- Test security identifier definition, access, and programming flow in both pre-silicon and post-silicon environments.

## Example instances (payload / topology hints)

- A system contains a register (divided into four 32-bit registers) that is used to store a 128-bit AES key for encryption/decryption, in addition to an access-policy register. The access-policy register determines which agents may access the AES-key registers, based on a corresponding security identifier. It is assumed the system has two agents: a Main-controller and an Aux-controller, with respec…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-1](CAPEC-1.md)
- ChildOf → [CAPEC-180](CAPEC-180.md)

## Related CWEs (run the cwe skill)

- [CWE-1259](../cwe/references/CWE-1259.md) — run that CWE procedure after this CAPEC flow
- [CWE-1267](../cwe/references/CWE-1267.md) — run that CWE procedure after this CAPEC flow
- [CWE-1270](../cwe/references/CWE-1270.md) — run that CWE procedure after this CAPEC flow
- [CWE-1294](../cwe/references/CWE-1294.md) — run that CWE procedure after this CAPEC flow
- [CWE-1302](../cwe/references/CWE-1302.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-681 and CWE IDs
