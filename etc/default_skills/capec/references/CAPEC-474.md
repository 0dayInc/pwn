# CAPEC-474: Signature Spoofing by Key Theft

- Catalog: [CAPEC-474](https://capec.mitre.org/data/definitions/474.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker obtains an authoritative or reputable signer's private signature key by theft and then uses this key to forge signatures from the original signer to mislead a victim into performing actions that benefit the attacker.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-474 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-474 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-474`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- An authoritative or reputable signer is storing their private signature key with insufficient protection.

## Skills required

- Low: Knowledge of common location methods and access methods to sensitive data
- High: Ability to compromise systems containing sensitive data

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Restrict access to private keys from non-supervisory accounts
- Restrict access to administrative personnel and processes only
- Ensure all remote methods are secured
- Ensure all services are patched and up to date

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-473](CAPEC-473.md)

## Related CWEs (run the cwe skill)

- [CWE-522](../cwe/references/CWE-522.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-474 and CWE IDs
