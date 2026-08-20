# CAPEC-679: Exploitation of Improperly Configured or Implemented Memory Protections

- Catalog: [CAPEC-679](https://capec.mitre.org/data/definitions/679.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary takes advantage of missing or incorrectly configured access control within memory to read/write data or inject malicious code into said memory.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-679 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-679 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-679`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- Access to the hardware being leveraged.

## Skills required

- Medium: Ability to craft malicious code to inject into the memory region.
- High: Intricate knowledge of memory structures.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Ensure that protected and unprotected memory ranges are isolated and do not overlap.
- If memory regions must overlap, leverage memory priority schemes if memory regions can overlap.
- Ensure that original and mirrored memory regions apply the same protections.
- Ensure immutable code or data is programmed into ROM or write-once memory.

## Example instances (payload / topology hints)

- A hardware product contains non-volatile memory, which itself contains boot code that is insufficiently protected. An adversary then modifies this memory to either bypass the secure boot process or to execute their own code.
- A hardware product leverages a CPU that does not possess a memory-protection unit (MPU) and a memory-management unit (MMU) nor a special bit to support write exclusivity, resulting in no write exclusivity. Because of this, an adversary is able to inject malicious code into the memory and later execute it to achieve the desired outcome.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-1](CAPEC-1.md)
- ChildOf → [CAPEC-180](CAPEC-180.md)

## Related CWEs (run the cwe skill)

- [CWE-1222](../cwe/references/CWE-1222.md) — run that CWE procedure after this CAPEC flow
- [CWE-1252](../cwe/references/CWE-1252.md) — run that CWE procedure after this CAPEC flow
- [CWE-1257](../cwe/references/CWE-1257.md) — run that CWE procedure after this CAPEC flow
- [CWE-1260](../cwe/references/CWE-1260.md) — run that CWE procedure after this CAPEC flow
- [CWE-1274](../cwe/references/CWE-1274.md) — run that CWE procedure after this CAPEC flow
- [CWE-1282](../cwe/references/CWE-1282.md) — run that CWE procedure after this CAPEC flow
- [CWE-1312](../cwe/references/CWE-1312.md) — run that CWE procedure after this CAPEC flow
- [CWE-1316](../cwe/references/CWE-1316.md) — run that CWE procedure after this CAPEC flow
- [CWE-1326](../cwe/references/CWE-1326.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-679 and CWE IDs
