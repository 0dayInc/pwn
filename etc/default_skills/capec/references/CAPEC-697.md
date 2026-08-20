# CAPEC-697: DHCP Spoofing

- Catalog: [CAPEC-697](https://capec.mitre.org/data/definitions/697.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary masquerades as a legitimate Dynamic Host Configuration Protocol (DHCP) server by spoofing DHCP traffic, with the goal of redirecting network traffic or denying service to DHCP.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-697 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::TransparentBrowser, PWN::Plugins::URIScheme; PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-697 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-697`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine Exsisting DHCP lease] An adversary observes network traffic and waits for an existing DHCP lease to expire on a target machine in the LAN. | techniques: Adversary observes LAN traffic for DHCP solicitations
- Step 2 (Experiment): [Capture the DHCP DISCOVER message] The adversary captures "DISCOVER" messages and crafts "OFFER" responses for the identified target MAC address. The success of this attack centers on the capturing of and responding to these "DISCOVER" messages. | techniques: Adversary captures and responds to DHCP "DISCOVER" messages tailored to the target subnet.
- Step 3 (Exploit): [Compromise Network Access and Collect Network Activity] An adversary successfully acts as a rogue DHCP server by redirecting legitimate DHCP requests to itself. | techniques: Adversary sends repeated DHCP "REQUEST" messages to quickly lease all the addresses within network's DHCP pool and forcing new DHCP requests to be handled by the rogue DHCP server.

## Prerequisites

- The adversary must have access to a machine within the target LAN which can send DHCP offers to the target.

## Skills required

- Medium: The adversary must identify potential targets for DHCP Spoofing and craft network configurations to obtain the desired results.

## Resources required

- The adversary requires access to a machine within the target LAN on a network which does not secure its DHCP traffic through MAC-Forced Forwarding, port security, etc.

## Oracles (consequences)

- Confidentiality, Access Control: Read Data
- Integrity, Access Control: Modify Data, Execute Unauthorized Commands
- Availability: Resource Consumption

## Mitigations to bypass

- Design: MAC-Forced Forwarding
- Implementation: Port Security and DHCP snooping
- Implementation: Network-based Intrusion Detection Systems

## Example instances (payload / topology hints)

- In early 2019, Microsoft patched a critical vulnerability (CVE-2019-0547) in the Windows DHCP client which allowed remote code execution via crafted DHCP OFFER packets. [REF-739]

## Related CAPECs (test these too)

- ChildOf → [CAPEC-194](CAPEC-194.md)
- CanPrecede → [CAPEC-158](CAPEC-158.md)
- CanPrecede → [CAPEC-94](CAPEC-94.md)

## Related CWEs (run the cwe skill)

- [CWE-923](../cwe/references/CWE-923.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-697 and CWE IDs
