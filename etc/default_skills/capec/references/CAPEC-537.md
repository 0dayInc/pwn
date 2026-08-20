# CAPEC-537: Infiltration of Hardware Development Environment

- Catalog: [CAPEC-537](https://capec.mitre.org/data/definitions/537.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary, leveraging the ability to manipulate components of primary support systems and tools within the development and production environments, inserts malicious software within the hardware and/or firmware development environment. The infiltration purpose is to alter developed hardware components in a system destined for deployment at the victim's organization, for the purpose of disruption or further compromise.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-537 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-537 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-537`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The victim must use email or removable media from systems running the IDE (or systems adjacent to the IDE systems).
- The victim must have a system running exploitable applications and/or a vulnerable configuration to allow for initial infiltration.
- The adversary must have working knowledge of some if not all of the components involved in the IDE system as well as the infrastructure.

## Skills required

- Medium: Intelligence about the manufacturer's operating environment and infrastructure.
- High: Ability to develop, deploy, and maintain a stealth malicious backdoor program remotely in what is essentially a hostile environment.
- High: Development skills to construct malicious attachments that can be used to exploit vulnerabilities in typical desktop applications or system configurations. The malicious attachments should be crafted well enough to bypass typical defensive systems (IDS, anti-virus, etc)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Verify software downloads and updates to ensure they have not been modified be adversaries
- Leverage antivirus tools to detect known malware
- Do not download software from untrusted sources
- Educate designers, developers, engineers, etc. on social engineering attacks to avoid downloading malicious software via attacks such as phishing attacks

## Example instances (payload / topology hints)

- The adversary, knowing the manufacturer runs email on a system adjacent to the hardware development systems used for hardware and/or firmware design, sends a phishing email with a malicious attachment to the manufacturer. When viewed, the malicious attachment installs a backdoor that allows the adversary to remotely compromise the adjacent hardware development system from the manufacturer's works…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-444](CAPEC-444.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-537 and CWE IDs
