# CAPEC-176: Configuration/Environment Manipulation

- Catalog: [CAPEC-176](https://capec.mitre.org/data/definitions/176.html)
- Abstraction: Meta · Status: Draft
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An attacker manipulates files or settings external to a target application which affect the behavior of that application. For example, many applications use external configuration files and libraries - modification of these entities or otherwise affecting the application's ability to use them would constitute a configuration/environment manipulation attack.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-176 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-176 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-176`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The target application must consult external files or configuration controls to control its execution. All but the very simplest applications meet this requirement.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- The attacker must have the access necessary to affect the files or other environment items the targeted application uses for its operations.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- [CWE-15](../cwe/references/CWE-15.md) — run that CWE procedure after this CAPEC flow
- [CWE-1233](../cwe/references/CWE-1233.md) — run that CWE procedure after this CAPEC flow
- [CWE-1234](../cwe/references/CWE-1234.md) — run that CWE procedure after this CAPEC flow
- [CWE-1304](../cwe/references/CWE-1304.md) — run that CWE procedure after this CAPEC flow
- [CWE-1328](../cwe/references/CWE-1328.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-176 and CWE IDs
