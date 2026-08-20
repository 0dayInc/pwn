# CAPEC-416: Manipulate Human Behavior

- Catalog: [CAPEC-416](https://capec.mitre.org/data/definitions/416.html)
- Abstraction: Meta · Status: Stable
- Likelihood of attack: Medium · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary exploits inherent human psychological predisposition to influence a targeted individual or group to solicit information or manipulate the target into performing an action that serves the adversary's interests. Many interpersonal social engineering techniques do not involve outright deception, although they can; many are subtle ways of manipulating a target to remove barriers, make the target feel comfortable, and produce an exchange in which the target is either more likely to share information directly, or let key information slip out unintentionally. A skilled adversary uses these techniques when appropriate to produce the desired outcome. Manipulation techniques vary from the overt, such as pretending to be a supervisor to a help desk, to the subtle, such as making the target feel comfortable with the adversary's speech and thought patterns.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-416 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

social-engineering skill, PWN::Plugins::MailAgent

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-416 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-416`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The adversary must have the means and knowledge of how to communicate with the target in some manner.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Other — Attack patterns that manipulate human behavior can result in a wide variety of consequences and potentially affect the confidentiality, availability, and/or integrity of an application or system.

## Mitigations to bypass

- An organization should provide regular, robust cybersecurity training to its employees to prevent successful social engineering attacks.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-416 and CWE IDs
