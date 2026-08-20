# CAPEC-700: Network Boundary Bridging

- Catalog: [CAPEC-700](https://capec.mitre.org/data/definitions/700.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary which has gained elevated access to network boundary devices may use these devices to create a channel to bridge trusted and untrusted networks. Boundary devices do not necessarily have to be on the network’s edge, but rather must serve to segment portions of the target network the adversary wishes to cross into.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-700 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-700 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-700`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify potential targets] An adversary identifies network boundary devices that can be compromised. | techniques: The adversary traces network traffic to identify which devices the traffic flows through. Additionally, the adversary can identify devices using fingerprinting methods or locating the management page to determine identi…
- Step 2 (Experiment): [Compromise targets] The adversary must compromise the identified targets in the previous step. | techniques: Once the device is identified, the adversary can attempt to input known default credentials for the device to gain access to the management console.; Adversaries with sufficient identifying knowledge about the target device can exploit known vulnerabilities in network…
- Step 3 (Exploit): [Bridge Networks] The adversary changes the configuration of the compromised network device to connect the networks the device was segmenting. Depending on the type of network boundary device and its capabilities, bridging can be implemented using various methods. | techniques: The adversary can abuse Network Address Translation (NAT) in firewalls and routers to manipulate traff…

## Prerequisites

- The adversary must have control of a network boundary device.

## Skills required

- Medium: The adversary must understand how to manage the target network device to create or edit policies which will bridge networks.

## Resources required

- The adversary requires either high privileges or full control of a boundary device on a target network.

## Oracles (consequences)

- Confidentiality, Access Control: Read Data, Bypass Protection Mechanism
- Integrity, Authorization: Alter Execution Logic, Hide Activities

## Mitigations to bypass

- Design: Ensure network devices are storing credentials in encrypted stores
- Design: Follow the principle of least privilege and restrict administrative duties to as few accounts as possible. Ensure these privileged accounts are secured with strong credentials which do not overlap with other network devices.
- Configuration: When possible, configure network boundary devices to use MFA.
- Configuration: Change the default configuration for network devices to harden their security profiles. Default configurations are often enabled with insecure features to allow ease of installation and management. However, these configurations can be easily discovered and exploited by adversaries.
- Implementation: Perform integrity checks on audit logs for network device management and review them to identify abnormalities in configurations.
- Implementation: Prevent network boundary devices from being physically accessed by unauthorized personnel to prevent tampering.

## Example instances (payload / topology hints)

- In November 2016, a Smart Install Exploitation Tool was released online which takes advantage of Cisco’s unauthenticated SMI management protocol to download a target’s current configuration files. Adversaries can use this tool to overwrite files to modify the device configurations, or upload maliciously modified OS or firmware to enable persistence. Once the adversary has access to the device’s c…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-161](CAPEC-161.md)
- CanFollow → [CAPEC-70](CAPEC-70.md)
- CanFollow → [CAPEC-560](CAPEC-560.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-700 and CWE IDs
