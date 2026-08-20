# CAPEC-157: Sniffing Attacks

- Catalog: [CAPEC-157](https://capec.mitre.org/data/definitions/157.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient. Sniffing Attacks are similar to Adversary-In-The-Middle attacks (CAPEC-94), but are entirely passive. AiTM attacks are predominantly active and often alter the content of the communications themselves.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-157 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-157 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-157`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine Communication Mechanism] The adversary determines the nature and mechanism of communication between two components, looking for opportunities to exploit. | techniques: Look for application documentation that might describe a communication mechanism used by a target.
- Step 2 (Experiment): [Position In Between Targets] The adversary positions themselves somewhere in the middle of the two components. If the communication is encrypted, the adversary will need to act as a proxy and route traffic between the components, exploiting a flaw in the encryption mechanism. Otherwise, the adversary can just observe the communication at either end. | techniques: Use Wiresha…
- Step 3 (Exploit): [Listen to Communication] The adversary observes communication, but does not alter or block it. The adversary gains access to sensitive information and can potentially utilize this information in a malicious way.

## Prerequisites

- The target data stream must be transmitted on a medium to which the adversary has access.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- The adversary must be able to intercept the transmissions containing the data of interest. Depending on the medium of transmission and the path the data takes between the sender and recipient, the adversary may require special equipment and/or require that this equipment be placed in specific locations (e.g., a network sniffing tool)

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-117](CAPEC-117.md)
- CanPrecede → [CAPEC-652](CAPEC-652.md)

## Related CWEs (run the cwe skill)

- [CWE-311](../cwe/references/CWE-311.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-157 and CWE IDs
