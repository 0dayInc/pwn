# CAPEC-516: Hardware Component Substitution During Baselining

- Catalog: [CAPEC-516](https://capec.mitre.org/data/definitions/516.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary with access to system components during allocated baseline development can substitute a maliciously altered hardware component for a baseline component during the product development and research phases. This can lead to adjustments and calibrations being made in the product so that when the final product, now containing the modified component, is deployed it will not perform as designed and be advantageous to the adversary.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-516 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-516 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-516`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The adversary will need either physical access or be able to supply malicious hardware components to the product development facility.

## Skills required

- Medium: Intelligence data on victim's purchasing habits.
- High: Resources to maliciously construct/alter hardware components used for testing by the supplier.
- High: Resources to physically infiltrate supplier.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Hardware attacks are often difficult to detect, as inserted components can be difficult to identify or remain dormant for an extended period of time.
- Acquire hardware and hardware components from trusted vendors. Additionally, determine where vendors purchase components or if any components are created/acquired via subcontractors to determine where supply chain risks may exist.

## Example instances (payload / topology hints)

- An adversary supplies the product development facility of a network security device with a hardware component that is used to simulate large volumes of network traffic. The device claims in logs, stats, and via the display panel to be pumping out very large quantities of network traffic, when it is in fact putting out very low volumes. The developed product is adjusted and configured to handle wh…

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
- [ ] Finding (if any) cites CAPEC-516 and CWE IDs
