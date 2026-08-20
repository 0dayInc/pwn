# CAPEC-523: Malicious Software Implanted

- Catalog: [CAPEC-523](https://capec.mitre.org/data/definitions/523.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker implants malicious software into the system in the supply chain distribution channel, with purpose of causing malicious disruption or allowing for additional compromise when the system is deployed.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-523 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-523 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-523`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine Entry Point] The adversary must first identify a system that they wish to target and search for an entry point they can use to install the malicious software. This could be a system which they have prior knowledge of, giving them insight into the software and environment. | techniques: Use a JTAGulator to identify exposed JTAG and UART interfaces in smaller embedded s…
- Step 2 (Explore): [Discover Vulnerability in Supply Chain] The adversary maps out the supply chain for the targeted system. They look for ooportunities to gain physical access to the system after it has left the manufacturer, but before it is deployed to the victim. | techniques: Procure a system and observe the steps it takes in the shipment process.; Identify possible warehouses that systems ar…
- Step 3 (Experiment): [Test Malicious Software] Before performing the attack in the wild, an adversary will test the attack on a system they have procured to ensure that the desired outcome will be achieved. | techniques: Design malicious software that will give an adversary a backdoor into the system once it is deployed to the victim.; Obtain already designed malicious software that just need to…
- Step 4 (Exploit): [Implant Software in the Supply Chain] Using the vulnerability in the supply chain of the system discovered in the explore phase, the adversary implants the malicious software into the system. This results in the adversary gaining unintended access to systems once they reach the victim and can lead to a variety of follow up attacks.

## Prerequisites

- Physical access to the system after it has left the manufacturer but before it is deployed at the victim location.

## Skills required

- High: Advanced knowledge of the design of the system and it's operating system components and subcomponents.
- High: Malicious software creation.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Deploy strong code integrity policies to allow only authorized apps to run.
- Use endpoint detection and response solutions that can automaticalkly detect and remediate suspicious activities.
- Maintain a highly secure build and update infrastructure by immediately applying security patches for OS and software, implementing mandatory integrity controls to ensure only trusted tools run, and requiring multi-factor authentication for admins.
- Require SSL for update channels and implement certificate transparency based verification.
- Sign everything, including configuration files, XML files and packages.
- Develop an incident response process, disclose supply chain incidents and notify customers with accurate and timely information.

## Example instances (payload / topology hints)

- An attacker has created a piece of malicious software designed to function as a backdoor in a system that is to be deployed at the victim location. During shipment of the system, the attacker has physical access to the system at a loading dock of an integrator for a short time. The attacker unpacks and powers up the system and installs the malicious piece of software, and configures it to run upo…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-439](CAPEC-439.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-523 and CWE IDs
