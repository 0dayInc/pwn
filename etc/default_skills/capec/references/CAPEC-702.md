# CAPEC-702: Exploiting Incorrect Chaining or Granularity of Hardware Debug Components

- Catalog: [CAPEC-702](https://capec.mitre.org/data/definitions/702.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary exploits incorrect chaining or granularity of hardware debug components in order to gain unauthorized access to debug functionality on a chip. This happens when authorization is not checked on a per function basis and is assumed for a chain or group of debug functionality.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-702 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-702 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-702`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find and scan debug interface] The adversary must first find and scan a debug interface to determine what they are authorized to use and what devices are chained to that interface. | techniques: Use a JTAGulator on a JTAG interface to determine the correct pin configuration, baud rate, and number of devices in the chain
- Step 2 (Experiment): [Connect to debug interface] The adversary next connects a device to the JTAG interface using the properties found in the explore phase so that they can send commands. The adversary sends some test commands to make sure the connection is working. | techniques: Connect a device such as a BusPirate or UM232H to the JTAG interface and connect using pin layout found from the JTAG…
- Step 3 (Exploit): [Move along debug chain] Once the adversary has connected to the main TAP, or JTAG interface, they will move along the TAP chain to see what debug interfaces might be available on that chain. | techniques: Run a command such as “scan_chain” to see what TAPs are available in the chain.

## Prerequisites

- Hardware device has an exposed debug interface

## Skills required

- Medium: Ability to identify physical debug interfaces on a device
- Medium: Ability to operate devices to scan and connect to an exposed debug interface

## Resources required

- A device to scan a TAP or JTAG interface, such as a JTAGulator
- A device to communicate on a TAP or JTAG interface, such as a BusPirate

## Oracles (consequences)

- Confidentiality: Read Data
- Integrity: Modify Data
- Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Implement: Ensure that debug components are properly chained, and their granularity is maintained at different authorization levels
- Perform Post-silicon validation tests at various authorization levels to ensure that debug components are only accessible to authorized users

## Example instances (payload / topology hints)

- A System-on-Chip (SoC) might give regular users access to the SoC-level TAP, but does not want to give access to all of the internal TAPs (e.g., Core). If any of the internal TAPs were incorrectly chained to the SoC-level TAP, this would grant regular users access to the internal TAPs and allow them to execute commands there.
- Suppose there is a hierarchy of TAPs (TAP_A is connected to TAP_B and TAP_C, then TAP_B is connected to TAP_D and TAP_E, then TAP_C is connected to TAP_F and TAP_G, etc.). Architecture mandates that the user have one set of credentials for just accessing TAP_A, another set of credentials for accessing TAP_B and TAP_C, etc. However, if, during implementation, the designer mistakenly implements a d…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-180](CAPEC-180.md)

## Related CWEs (run the cwe skill)

- [CWE-1296](../cwe/references/CWE-1296.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-702 and CWE IDs
