# CAPEC-548: Contaminate Resource

- Catalog: [CAPEC-548](https://capec.mitre.org/data/definitions/548.html)
- Abstraction: Meta · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary contaminates organizational information systems (including devices and networks) by causing them to handle information of a classification/sensitivity for which they have not been authorized. When this happens, the contaminated information system, device, or network must be brought offline to investigate and mitigate the data spill, which denies availability of the system until the investigation is complete.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-548 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-548 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-548`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The adversary needs to have real or fake classified/sensitive information to place on a system

## Skills required

- Low: Knowledge of classification levels of systems
- High: The ability to obtain a classified document or information
- Low: The ability to fake a classified document

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Availability: Resource Consumption — Denial of Service
- Confidentiality: Read Data — Victims of the attack can be exposed to classified materials

## Mitigations to bypass

- Properly safeguard classified/sensitive data. This includes training cleared individuals to ensure they are handling and disposing of this data properly, as well as ensuring systems only handle information of the classification level they are designed for.
- Design systems with redundancy in mind. This could mean creating backing servers that could be switched over to in the event that a server has to be taken down for investigation.
- Have a planned and efficient response plan to limit the amount of time a system is offline while the contamination is investigated.

## Example instances (payload / topology hints)

- An insider threat was able to obtain a classified document. They have knowledge that a backend server which provides access to a website also runs a mail server. The adversary creates a throwaway email address and sends the classified document to the mail server. When an administrator checks the mail server they notice that it has processed an email with a classified document and the server has t…

## Related CAPECs (test these too)

- CanPrecede → [CAPEC-607](CAPEC-607.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-548 and CWE IDs
