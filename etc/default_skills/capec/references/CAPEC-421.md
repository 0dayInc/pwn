# CAPEC-421: Influence Perception of Authority

- Catalog: [CAPEC-421](https://capec.mitre.org/data/definitions/421.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: High · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

An adversary uses a social engineering technique to convey a sense of authority that motivates the target to reveal specific information or take specific action. There are various techniques for producing a sense of authority during ordinary modes of communication. One common method is impersonation. By impersonating someone with a position of power within an organization, an adversary may motivate the target individual to reveal some piece of sensitive information or perform an action that benefits the adversary.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-421 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

social-engineering skill, PWN::Plugins::MailAgent

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-421 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-421`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The adversary must have the means and knowledge of how to communicate with the target in some manner.

## Skills required

- Low: The adversary requires strong inter-personal and communication skills.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Other — Attacks that leverage the principle of scarcity can lead to the target performing an action that results in a variety of consequences that negatively affect the confidentiality, availability, and/or integrity of an application or system.

## Mitigations to bypass

- An organization should provide regular, robust cybersecurity training to its employees to prevent social engineering attacks.

## Example instances (payload / topology hints)

- The adversary calls the target and announces that they are the head of IT at the target's company. The adversary goes on to say that there has been a technical issue and they need the target's login credentials for their account. By convincing the target of their authority, the adversary hopes the target will reveal the sensitive information.

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
- [ ] Finding (if any) cites CAPEC-421 and CWE IDs
