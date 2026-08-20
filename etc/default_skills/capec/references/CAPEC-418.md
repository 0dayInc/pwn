# CAPEC-418: Influence Perception of Reciprocation

- Catalog: [CAPEC-418](https://capec.mitre.org/data/definitions/418.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary uses a social engineering techniques to produce a sense of obligation in the target to perform a certain action or concede some sensitive or key piece of information. Obligation has to do with actions one feels they need to take due to some sort of social, legal, or moral requirement, duty, contract, or promise. There are various techniques for fostering a sense of obligation to reciprocate or concede during ordinary modes of communication. One method is to compliment the target, and follow up the compliment with a question. If performed correctly the target may volunteer a key piece of information, sometimes involuntarily.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-418 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

social-engineering skill, PWN::Plugins::MailAgent

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-418 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-418`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The adversary must have the means and knowledge of how to communicate with the target in some manner.

## Skills required

- Low: The adversary requires strong inter-personal and communication skills.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Other — Attacks that influence the perception of the target can result in a wide variety of consequences and negatively affect potentially the confidentiality, availability, and/or integrity of an application or system.

## Mitigations to bypass

- An organization should provide regular, robust cybersecurity training to its employees to prevent social engineering attacks.

## Example instances (payload / topology hints)

- An adversary develops a relationship with the target to foster a feeling of obligation in them to perform a certain action or concede some information. A perception of obligation/concession means that the target feels they need to behave in some way or perform some sort of action due to being morally or legally bound to do so.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-417](CAPEC-417.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-418 and CWE IDs
