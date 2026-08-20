# CAPEC-530: Provide Counterfeit Component

- Catalog: [CAPEC-530](https://capec.mitre.org/data/definitions/530.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker provides a counterfeit component during the procurement process of a lower-tier component supplier to a sub-system developer or integrator, which is then built into the system being upgraded or repaired by the victim, allowing the attacker to cause disruption or additional compromise.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-530 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-530 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-530`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- Advanced knowledge about the target system and sub-components.

## Skills required

- High: Able to develop and manufacture malicious system components that resemble legitimate name-brand components.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- There are various methods to detect if the component is a counterfeit. See section II of [REF-703] for many techniques.

## Example instances (payload / topology hints)

- The attacker, aware that the victim has contracted with an integrator for system maintenance and that the integrator uses commercial-off-the-shelf network hubs, develops their own network hubs with a built-in malicious capability for remote access, the malicious network hubs appear to be a well-known brand of network hub but are not. The attacker then advertises to the sub-system integrator that…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-531](CAPEC-531.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-530 and CWE IDs
