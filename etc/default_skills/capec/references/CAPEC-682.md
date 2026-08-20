# CAPEC-682: Exploitation of Firmware or ROM Code with Unpatchable Vulnerabilities

- Catalog: [CAPEC-682](https://capec.mitre.org/data/definitions/682.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary may exploit vulnerable code (i.e., firmware or ROM) that is unpatchable. Unpatchable devices exist due to manufacturers intentionally or inadvertently designing devices incapable of updating their software. Additionally, with updatable devices, the manufacturer may decide not to support the device and stop making updates to their software.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-682 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-682 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-682`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine vulnerable firmware or ROM code] An adversary will attempt to find device models that are known to have unpatchable firmware or ROM code, or are deemed “end-of-support” where a patch will not be made. The adversary looks for vulnerabilities in firmware or ROM code for the identified devices, or looks for devices which have known vulnerabilities | techniques: Many botn…
- Step 2 (Experiment): [Determine plan of attack] An adversary identifies a specific device/model that they wish to attack. They will also investigate similar devices to determine if the vulnerable firmware or ROM code is also present.
- Step 3 (Exploit): [Carry out attack] An adversary exploits the vulnerable firmware or ROM code on the identified device(s) to achieve their desired goal. | techniques: Install malware on a device to recruit it for a botnet.; Install malware on the device and use it for a ransomware attack.; Gain root access and steal information stored on the device.; Manipulate the device to behave in unexpected…

## Prerequisites

- Awareness of the hardware being leveraged.
- Access to the hardware being leveraged, either physically or remotely.

## Skills required

- Medium: Knowledge of various wireless protocols to enable remote access to vulnerable devices
- High: Ability to identify physical entry points such as debug interfaces if the device is not being accessed remotely

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Design systems and products with the ability to patch firmware or ROM code after deployment to fix vulnerabilities.
- Make use of OTA (Over-the-air) updates so that firmware can be patched remotely either through manual or automatic means

## Example instances (payload / topology hints)

- An IoT company comes out with a line of smart products for home use such as home cameras, vacuums, and smart bulbs. The products become popular, and millions of consumers install these devices in their homes. All the devices use a custom module for encryption that is stored on a ROM chip, which is immutable memory and can't be changed. An adversary discovers that there is a vulnerability in the e…
- Older smartphones can become out of date and manufacturers may stop putting out security updates as they focus on newer models. If an adversary discovers a vulnerability in an old smartphone there is a chance that a security update will not be made to mitigate it. This leaves anyone using the old smartphone vulnerable.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-212](CAPEC-212.md)

## Related CWEs (run the cwe skill)

- [CWE-1277](../cwe/references/CWE-1277.md) — run that CWE procedure after this CAPEC flow
- [CWE-1310](../cwe/references/CWE-1310.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-682 and CWE IDs
