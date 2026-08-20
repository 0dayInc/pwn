# CAPEC-638: Altered Component Firmware

- Catalog: [CAPEC-638](https://capec.mitre.org/data/definitions/638.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Low · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits systems features and/or improperly protected firmware of hardware components, such as Hard Disk Drives (HDD), with the goal of executing malicious code from within the component's Master Boot Record (MBR). Conducting this type of attack entails the adversary infecting the target with firmware altering malware, using known tools, and a payload. Once this malware is executed, the MBR is modified to include instructions to execute the payload at desired intervals and when the system is booted up. A successful attack will obtain persistence within the victim system even if the operating system is reinstalled and/or if the component is formatted or has its data erased.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-638 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-638 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-638`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Select Target] The adversary searches for a suitable target to attack, such as government and/or private industry organizations. | techniques: Conduct reconnaissance to determine potential targets to exploit.
- Step 2 (Explore): [Identify Components] After selecting a target, the adversary determines whether a vulnerable component, such as a specific make and model of a HDD, is contained within the target system. | techniques: [Remote Access Vector] The adversary gains remote access to the target, typically via additional malware, and explores the system to determine hardware components that are being l…
- Step 3 (Experiment): [Optional: Create Payload] If not using an already existing payload, the adversary creates their own to be executed at defined intervals and upon system boot processes. This payload may then be tested on the target system or a test system to confirm its functionality.
- Step 4 (Exploit): [Insert Firmware Altering Malware] Once a vulnerable component has been identified, the adversary leverages known malware tools to infect the component's firmware and drop the payload within the component's MBR. This allows the adversary to maintain persistence on the target and execute the payload without being detected. | techniques: The adversary inserts the firmware altering…

## Prerequisites

- Advanced knowledge about the target component's firmware
- Advanced knowledge about Master Boot Records (MBR)
- Advanced knowledge about tools used to insert firmware altering malware.
- Advanced knowledge about component shipments to the target organization.

## Skills required

- High: Ability to access and reverse engineer hardware component firmware.
- High: Ability to intercept components in transit.
- Medium: Ability to create malicious payload to be executed from MBR.
- Low: Ability to leverage known malware tools to infect target system and insert firmware altering malware/payload

## Resources required

- Manufacturer source code for hardware components.
- Malware tools used to insert malware and payload onto target component.
- Either remote or physical access to the target component.

## Oracles (consequences)

- Authentication, Authorization: Gain Privileges, Execute Unauthorized Commands, Bypass Protection Mechanism, Hide Activities
- Confidentiality, Access Control: Read Data, Modify Data

## Mitigations to bypass

- Leverage hardware components known to not be susceptible to these types of attacks.
- Implement hardware RAID infrastructure.

## Example instances (payload / topology hints)

- In 2014, the Equation group was observed levering known malware tools to conduct component firmware alteration attacks against hard drives. In total, 12 HDD categories were shown to be vulnerable from manufacturers such as Western Digital, HGST, Samsung, and Seagate. Because of their complexity, only a few victims were targeted by these attacks. [REF-664]

## Related CAPECs (test these too)

- ChildOf → [CAPEC-452](CAPEC-452.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-638 and CWE IDs
