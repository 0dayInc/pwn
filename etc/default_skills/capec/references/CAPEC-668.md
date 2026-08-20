# CAPEC-668: Key Negotiation of Bluetooth Attack (KNOB)

- Catalog: [CAPEC-668](https://capec.mitre.org/data/definitions/668.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary can exploit a flaw in Bluetooth key negotiation allowing them to decrypt information sent between two devices communicating via Bluetooth. The adversary uses an Adversary in the Middle setup to modify packets sent between the two devices during the authentication process, specifically the entropy bits. Knowledge of the number of entropy bits will allow the attacker to easily decrypt information passing over the line of communication.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-668 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-668 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-668`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Discovery] Using an established Person in the Middle setup, search for Bluetooth devices beginning the authentication process. | techniques: Use packet capture tools.
- Step 2 (Experiment): [Change the entropy bits] Upon recieving the initial key negotiation packet from the master, the adversary modifies the entropy bits requested to 1 to allow for easy decryption before it is forwarded.
- Step 3 (Exploit): [Capture and decrypt data] Once the entropy of encryption is known, the adversary can capture data and then decrypt on their device.

## Prerequisites

- Person in the Middle network setup.

## Skills required

- Medium: Ability to modify packets.

## Resources required

- Bluetooth adapter, packet capturing capabilities.

## Oracles (consequences)

- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Bypass Protection Mechanism
- Integrity: Modify Data

## Mitigations to bypass

- Newer Bluetooth firmwares ensure that the KNOB is not negotaited in plaintext. Update your device.

## Example instances (payload / topology hints)

- Given users Alice, Bob and Charlie (Charlie being the attacker), Alice and Bob begin to agree on an encryption key when connecting. While Alice sends a message to Bob that an encryption key with 16 bytes of entropy should be used, Charlie changes this to 1 and forwards the request to Bob and continues forwarding these packets until authentication is successful.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-115](CAPEC-115.md)
- CanPrecede → [CAPEC-148](CAPEC-148.md)

## Related CWEs (run the cwe skill)

- [CWE-425](../cwe/references/CWE-425.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-668 and CWE IDs
