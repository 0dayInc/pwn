# CAPEC-116: Excavation

- Catalog: [CAPEC-116](https://capec.mitre.org/data/definitions/116.html)
- Abstraction: Meta · Status: Stable
- Likelihood of attack: High · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary actively probes the target in a manner that is designed to solicit information that could be leveraged for malicious purposes.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-116 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-116 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-116`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- An adversary requires some way of interacting with the system.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- A tool, such as an Adversary in the Middle (CAPEC-94) Proxy or a fuzzer, that is capable of generating and injecting custom inputs to be used in the attack.

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- Minimize error/response output to only what is necessary for functional use or corrective language.
- Remove potentially sensitive information that is not necessary for the application's functionality.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- CanPrecede → [CAPEC-163](CAPEC-163.md)

## Related CWEs (run the cwe skill)

- [CWE-200](../cwe/references/CWE-200.md) — run that CWE procedure after this CAPEC flow
- [CWE-1243](../cwe/references/CWE-1243.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-116 and CWE IDs
