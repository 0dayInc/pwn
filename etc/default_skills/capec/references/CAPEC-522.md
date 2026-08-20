# CAPEC-522: Malicious Hardware Component Replacement

- Catalog: [CAPEC-522](https://capec.mitre.org/data/definitions/522.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary replaces legitimate hardware in the system with faulty counterfeit or tampered hardware in the supply chain distribution channel, with purpose of causing malicious disruption or allowing for additional compromise when the system is deployed.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-522 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-522 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-522`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine Target Hardware] The adversary must first identify a system that they wish to target, and a specific hardware component that they can swap out with a malicious replacement. | techniques: Look for datasheets containing the system schematics that can help identify possible target hardware.; Procure a system and inspect it manually, looking for possible hardware componen…
- Step 2 (Explore): [Discover Vulnerability in Supply Chain] The adversary maps out the supply chain for the targeted system. They look for ooportunities to gain physical access to the system after it has left the manufacturer, but before it is deployed to the victim. | techniques: Procure a system and observe the steps it takes in the shipment process.; Identify possible warehouses that systems ar…
- Step 3 (Experiment): [Test a Malicious Component Replacement] Before performing the attack in the wild, an adversary will test the attack on a system they have procured to ensure that the desired outcome will be achieved. | techniques: Design a malicious hardware component that will perform the same functionality as the target component, but also contains additional functionality.; Obtain already…
- Step 3 (Exploit): [Substitute Components in the Supply Chain] Using the vulnerability in the supply chain of the system discovered in the explore phase, the adversary substitutes the malicious component for the targeted component. This results in the adversary gaining unintended access to systems once they reach the victim and can lead to a variety of follow up attacks.

## Prerequisites

- Physical access to the system after it has left the manufacturer but before it is deployed at the victim location.

## Skills required

- High: Advanced knowledge of the design of the system.
- High: Hardware creation and manufacture of replacement components.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Ensure that all contractors and sub-suppliers use trusted means of shipping (e.g., bonded/cleared/vetted and insured couriers) to ensure that components, once purchased, are not subject to compromise during their delivery.
- Prevent or detect tampering with critical hardware or firmware components while in transit through use of state-of-the-art anti-tamper devices.
- Use tamper-resistant and tamper-evident packaging when shipping critical components (e.g., plastic coating for circuit boards, tamper tape, paint, sensors, and/or seals for cases and containers) and inspect received system components for evidence of tampering.

## Example instances (payload / topology hints)

- During shipment the adversary is able to intercept a system that has been purchased by the victim, and replaces a math processor card that functions just like the original, but contains advanced malicious capability. Once deployed, the system functions as normal, but allows for the adversary to remotely communicate with the system and use it as a conduit for additional compromise within the victi…

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
- [ ] Finding (if any) cites CAPEC-522 and CWE IDs
