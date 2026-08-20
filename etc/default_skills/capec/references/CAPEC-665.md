# CAPEC-665: Exploitation of Thunderbolt Protection Flaws

- Catalog: [CAPEC-665](https://capec.mitre.org/data/definitions/665.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Low · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary leverages a firmware weakness within the Thunderbolt protocol, on a computing device to manipulate Thunderbolt controller firmware in order to exploit vulnerabilities in the implementation of authorization and verification schemes within Thunderbolt protection mechanisms. Upon gaining physical access to a target device, the adversary conducts high-level firmware manipulation of the victim Thunderbolt controller SPI (Serial Peripheral Interface) flash, through the use of a SPI Programing device and an external Thunderbolt device, typically as the target device is booting up. If successful, this allows the adversary to modify memory, subvert authentication mechanisms, spoof identities and content, and extract data and memory from the target device. Currently 7 major vulnerabilities exist within Thunderbolt protocol with 9 attack vectors as noted in the Execution Flow.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-665 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor; PWN::Plugins::Serial, PWN::Plugins::BusPirate; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-665 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-665`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey physical victim environment and potential Thunderbolt system targets] The adversary monitors the target's physical environment to identify systems with Thunderbolt interfaces, identify potential weaknesses in physical security in addition to periods of nonattendance by the victim over their Thunderbolt interface equipped devices, and when the devices are in locked or sle…
- Step 2 (Explore): [Evaluate the target system and its Thunderbolt interface] The adversary determines the device's operating system, Thunderbolt interface version, and any implemented Thunderbolt protections to plan the attack.
- Step 1 (Experiment): [Obtain and/or clone firmware image] The adversary physically manipulates Thunderbolt enabled devices to acquire the firmware image from the target and/or adversary Thunderbolt host controller's SPI (Serial Peripheral Interface) flash. | techniques: Disassemble victim and/or adversary device enclosure with basic tools to gain access to Thunderbolt controller SPI flash by conn…
- Step 2 (Experiment): [Parse and locate relevant firmware data structures and information based upon Thunderbolt controller model, firmware version, and other information] The acquired victim and/or adversary firmware image is parsed for specific data and other relevant identifiers required for exploitation, based upon the victim device information and firmware version. | techniques: Utilize pre-c…
- Step 3 (Experiment): [Disable Thunderbolt security and prevent future Thunderbolt security modifications (if necessary)] The adversary overrides the target device's Thunderbolt Security Level to "None" (SL0) and/or enables block protections upon the SPI flash to prevent the ability for the victim to perform and/or recognize future Thunderbolt security modifications as well as update the Thunderbo…
- Step 4 (Experiment): [Modify/replace victim Thunderbolt firmware image] The modified victim and/or adversary thunderbolt firmware image is written to attacker SPI flash.
- Step 1 (Exploit): [Connect adversary-controlled thunderbolt enabled device to victim device and verify successful execution of malicious actions] The adversary needs to determine if their exploitation of selected vulnerabilities had the intended effects upon victim device. | techniques: Observe victim device identify adversary device as the victim device and enables PCIe tunneling.; Resume victim…
- Step 2 (Exploit): [Exfiltration of desired data from victim device to adversary device] Utilize PCIe tunneling to transfer desired data and information from victim device across Thunderbolt connection.

## Prerequisites

- The adversary needs at least a few minutes of physical access to a system with an open Thunderbolt port, version 3 or lower, and an external thunderbolt device controlled by the adversary with maliciously crafted software and firmware, via an SPI Programming device, to exploit weaknesses in security protections.

## Skills required

- High: Detailed knowledge on various system motherboards, PCI Express Domain, SPI, and Thunderbolt Protocol in order to interface with internal system components via external devices.
- High: Detailed knowledge on OS/Kernel memory address space, Direct Memory Access (DMA) mapping, Input-Output Memory Management Units (IOMMUs), and vendor memory protections for data leakage.
- High: Detailed knowledge on scripting and SPI programming in order to configure and modify Thunderbolt controller firmware and software configurations.

## Resources required

- SPI Programming device capable of modifying/configuring or replacing the firmware of Thunderbolt device stored on SPI Flash of target Thunderbolt controller, as well as modification/spoofing of adversary-controlled Thunderbolt controller.
- Precrafted scripts/tools capable of implementing the modification and replacement of Thunderbolt Firmware.
- Thunderbolt-enabled computing device capable of interfacing with target Thunderbolt device and extracting/dumping data and memory contents of target device.

## Oracles (consequences)

- Access Control: Bypass Protection Mechanism
- Confidentiality: Read Data
- Integrity: Modify Data
- Authorization: Execute Unauthorized Commands

## Mitigations to bypass

- Implementation: Kernel Direct Memory Access Protection
- Configuration: Enable UEFI option USB Passthrough mode - Thunderbolt 3 system port operates as USB 3.1 Type C interface
- Configuration: Enable UEFI option DisplayPort mode - Thunderbolt 3 system port operates as video-only DP interface
- Configuration: Enable UEFI option Mixed USB/DisplayPort mode - Thunderbolt 3 system port operates as USB 3.1 Type C interface with support for DP mode
- Configuration: Set Security Level to SL3 for Thunderbolt 2 system port
- Configuration: Disable PCIe tunneling to set Security Level to SL3
- Configuration: Disable Boot Camp upon MacOS systems

## Example instances (payload / topology hints)

- An adversary steals a password protected laptop that contains a Thunderbolt 3 enabled port, from a work environment. The adversary uses a screw driver to remove the back panel of the laptop and connects a SPI Programming device to the Thunderbolt Host Controller SPI Flash of the stolen victim device to interface with it on the adversary's own Thunderbolt enabled device via Thunderbolt cables. The…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-276](CAPEC-276.md)
- CanFollow → [CAPEC-390](CAPEC-390.md)
- PeerOf → [CAPEC-458](CAPEC-458.md)
- PeerOf → [CAPEC-148](CAPEC-148.md)
- PeerOf → [CAPEC-151](CAPEC-151.md)

## Related CWEs (run the cwe skill)

- [CWE-345](../cwe/references/CWE-345.md) — run that CWE procedure after this CAPEC flow
- [CWE-353](../cwe/references/CWE-353.md) — run that CWE procedure after this CAPEC flow
- [CWE-288](../cwe/references/CWE-288.md) — run that CWE procedure after this CAPEC flow
- [CWE-1188](../cwe/references/CWE-1188.md) — run that CWE procedure after this CAPEC flow
- [CWE-862](../cwe/references/CWE-862.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-665 and CWE IDs
