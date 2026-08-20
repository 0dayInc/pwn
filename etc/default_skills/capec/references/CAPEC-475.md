# CAPEC-475: Signature Spoofing by Improper Validation

- Catalog: [CAPEC-475](https://capec.mitre.org/data/definitions/475.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits a cryptographic weakness in the signature verification algorithm implementation to generate a valid signature without knowing the key.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-475 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-475 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-475`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- Recipient is using a weak cryptographic signature verification algorithm or a weak implementation of a cryptographic signature verification algorithm, or the configuration of the recipient's application accepts the use of keys generated using cryptographically weak signature verification algorithms.

## Skills required

- High: Cryptanalysis of signature verification algorithm
- High: Reverse engineering and cryptanalysis of signature verification algorithm implementation

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Use programs and products that contain cryptographic elements that have been thoroughly tested for flaws in the signature verification routines.

## Example instances (payload / topology hints)

- The Windows CryptoAPI (Crypt32.dll) was shown to be vulnerable to signature spoofing by failing to properly validate Elliptic Curve Cryptography (ECC) certificates. If the CryptoAPI's signature validator allows the specification of a nonstandard base point (G): "An adversary can create a custom ECDSA certificate with an elliptic curve (ECC) signature that appears to match a known standard curve,…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-473](CAPEC-473.md)
- CanPrecede → [CAPEC-542](CAPEC-542.md)

## Related CWEs (run the cwe skill)

- [CWE-347](../cwe/references/CWE-347.md) — run that CWE procedure after this CAPEC flow
- [CWE-327](../cwe/references/CWE-327.md) — run that CWE procedure after this CAPEC flow
- [CWE-295](../cwe/references/CWE-295.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-475 and CWE IDs
