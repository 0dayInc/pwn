# CAPEC-680: Exploitation of Improperly Controlled Registers

- Catalog: [CAPEC-680](https://capec.mitre.org/data/definitions/680.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits missing or incorrectly configured access control within registers to read/write data that is not meant to be obtained or modified by a user.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-680 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-680 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-680`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- Awareness of the hardware being leveraged.
- Access to the hardware being leveraged.

## Skills required

- High: Intricate knowledge of registers.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data

## Mitigations to bypass

- Design proper access control policies for hardware register access from software and ensure these policies are implemented in accordance with the specified design.
- Ensure security lock bit protections are reviewed for design inconsistencies and common weaknesses.
- Test security lock programming flow in both pre-silicon and post-silicon environments.
- Leverage automated tools to test that values are not reprogrammable and that write-once fields lock on writing zeros.
- Ensure that measurement data is stored in registers that are read-only or otherwise have access controls that prevent modification by an untrusted agent.

## Example instances (payload / topology hints)

- During a System-on-Chip's (SoC) secure boot process, the code to be authenticated is measured to determine the code's validity. This entails the one-way hash of the code binary being calculated and extended to the previous hash. The value obtained after completion of the boot flow is then stored in a register with the intent of later verifying this value to determine if the boot flow has been tam…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-1](CAPEC-1.md)
- ChildOf → [CAPEC-180](CAPEC-180.md)

## Related CWEs (run the cwe skill)

- [CWE-1224](../cwe/references/CWE-1224.md) — run that CWE procedure after this CAPEC flow
- [CWE-1231](../cwe/references/CWE-1231.md) — run that CWE procedure after this CAPEC flow
- [CWE-1233](../cwe/references/CWE-1233.md) — run that CWE procedure after this CAPEC flow
- [CWE-1262](../cwe/references/CWE-1262.md) — run that CWE procedure after this CAPEC flow
- [CWE-1283](../cwe/references/CWE-1283.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-680 and CWE IDs
