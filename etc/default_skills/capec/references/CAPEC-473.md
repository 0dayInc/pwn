# CAPEC-473: Signature Spoof

- Catalog: [CAPEC-473](https://capec.mitre.org/data/definitions/473.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: not stated · Typical severity: not stated
- CAPEC list: 3.9

## Attack pattern

An attacker generates a message or datablock that causes the recipient to believe that the message or datablock was generated and cryptographically signed by an authoritative or reputable source, misleading a victim or victim operating system into performing malicious actions.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-473 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-473 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-473`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The victim or victim system is dependent upon a cryptographic signature-based verification system for validation of one or more security events or actions.
- The validation can be bypassed via an attacker-provided signature that makes it appear that the legitimate authoritative or reputable source provided the signature.

## Skills required

- High: Technical understanding of how signature verification algorithms work with data and applications

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Access Control, Authentication: Gain Privileges

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- An attacker provides a victim with a malicious executable disguised as a legitimate executable from an established software by signing the executable with a forged cryptographic key. The victim's operating system attempts to verify the executable by checking the signature, the signature is considered valid, and the attackers' malicious executable runs.
- An attacker exploits weaknesses in a cryptographic algorithm to that allow a private key for a legitimate software vendor to be reconstructed, attacker-created malicious software is cryptographically signed with the reconstructed key, and is installed by the victim operating system disguised as a legitimate software update from the software vendor.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-151](CAPEC-151.md)

## Related CWEs (run the cwe skill)

- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-327](../cwe/references/CWE-327.md) — run that CWE procedure after this CAPEC flow
- [CWE-290](../cwe/references/CWE-290.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-473 and CWE IDs
