# CAPEC-456: Infected Memory

- Catalog: [CAPEC-456](https://capec.mitre.org/data/definitions/456.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary inserts malicious logic into memory enabling them to achieve a negative impact. This logic is often hidden from the user of the system and works behind the scenes to achieve negative impacts. This pattern of attack focuses on systems already fielded and used in operation as opposed to systems that are still under development and part of the supply chain.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-456 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-456 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-456`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- (none listed in CAPEC catalog)

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Authorization: Execute Unauthorized Commands

## Mitigations to bypass

- Leverage anti-virus products to detect stop operations with known virus.

## Example instances (payload / topology hints)

- A USB Memory stick has malicious logic inserted before shipping of the product allowing for infection of the host machine once inserted into the USB port.
- In 2007, approximately 1800 of Seagate's Maxtor Personal Storage 3200 drives were built under contract with an outside manufacturer and contained a virus that stole user passwords.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-441](CAPEC-441.md)

## Related CWEs (run the cwe skill)

- [CWE-1257](../cwe/references/CWE-1257.md) — run that CWE procedure after this CAPEC flow
- [CWE-1260](../cwe/references/CWE-1260.md) — run that CWE procedure after this CAPEC flow
- [CWE-1274](../cwe/references/CWE-1274.md) — run that CWE procedure after this CAPEC flow
- [CWE-1312](../cwe/references/CWE-1312.md) — run that CWE procedure after this CAPEC flow
- [CWE-1316](../cwe/references/CWE-1316.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-456 and CWE IDs
