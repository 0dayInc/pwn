# CAPEC-425: Target Influence via Framing

- Catalog: [CAPEC-425](https://capec.mitre.org/data/definitions/425.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Low · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

An adversary uses framing techniques to contextualize a conversation so that the target is more likely to be influenced by the adversary's point of view. Framing is information and experiences in life that alter the way we react to decisions we must make. This type of persuasive technique exploits the way people are conditioned to perceive data and its significance, while avoiding negative or avoidance responses from the target. Rather than a specific technique framing is a methodology of conversation that slowly encourages the target to adopt to the adversary's perspective. One technique of framing is to avoid the use of the word "No" and to contextualize responses in a manner that is positive. When performed skillfully the target is much more likely to volunteer information or perform actions favorable to the adversary.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-425 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-425 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-425`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The adversary must have the means and knowledge of how to communicate with the target in some manner.

## Skills required

- Low: The adversary requires strong inter-personal and communication skills.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality: Other — Successful attacks that influence the target via framing into performing an action or sharing sensitive information can result in a variety of consequences that negatively affect the confidentiality of an application or system.

## Mitigations to bypass

- An organization should provide regular, robust cybersecurity training to its employees to prevent social engineering attacks.
- Avoid sharing unnecessary information during interactions beyond what is absolutely required for effective communication.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-416](CAPEC-416.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-425 and CWE IDs
