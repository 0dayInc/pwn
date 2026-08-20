# CAPEC-699: Eavesdropping on a Monitor

- Catalog: [CAPEC-699](https://capec.mitre.org/data/definitions/699.html)
- Abstraction: Meta · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An Adversary can eavesdrop on the content of an external monitor through the air without modifying any cable or installing software, just capturing this signal emitted by the cable or video port, with this the attacker will be able to impact the confidentiality of the data without being detected by traditional security tools

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-699 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SDR, extro_rf_tune

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-699 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-699`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey Target] The adversary surveys the target location, looking for exposed display cables and locations to hide an SDR. This also includes looking for display cables or monitors placed close to a wall, where the SDR can be in range while behind the wall. The adversary also attempts to discover the resolution and refresh rate of the targeted display.
- Step 2 (Experiment): [Find target using SDR] The adversary sets up an SDR near the target display cable or monitor. They use the SDR software to locate the corresponding frequency of the display cable. This is done by looking for interference peaks that change depending on what the screen is showing. The adversary notes down the possible frequencies of unintentional emission. | techniques: An adv…
- Step 3 (Exploit): [Visualize Monitor Image] Once the SDR software has been used to identify the target, the adversary will record the transmissions and visualize the monitor image using these transmissions, which allows them to eavesdrop on the information visible on the monitor. | techniques: The TempestSDR software can be used in conjunction an SDR device to visualize the monitor image. The adv…

## Prerequisites

- Victim should use an external monitor device
- Physical access to the target location and devices

## Skills required

- Medium: Knowledge of how to use the SDR and related software: With this knowledge, the adversary will find the correct frequency where the signal is being leaked
- Low: Understanding of computing hardware, to identify the video cable and video ports

## Resources required

- SDR device set with the correspondent antenna
- Computer with SDR Software

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- Enhance: Increase the number of electromagnetic shield layers in the display ports and cables to contain or reduce the intensity of the leaked signal.
- Implement: Use a protocol that encrypts the video signal; in case the signal is intercepted the signal is protected by the encryption.
- Design: Lock away the video cables, making it difficult for the attacker to access the cables and place the antenna near them (If the distance condition between the antenna and display port/cable is not satisfied, the attack will not be possible).
- Implement: Use wireless technologies to connect to external display devices.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-651](CAPEC-651.md)

## Related CWEs (run the cwe skill)

- [CWE-1300](../cwe/references/CWE-1300.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-699 and CWE IDs
