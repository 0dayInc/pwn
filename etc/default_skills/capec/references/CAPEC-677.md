# CAPEC-677: Server Motherboard Compromise

- Catalog: [CAPEC-677](https://capec.mitre.org/data/definitions/677.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

Malware is inserted in a server motherboard (e.g., in the flash memory) in order to alter server functionality from that intended. The development environment or hardware/software support activity environment is susceptible to an adversary inserting malicious software into hardware components during development or update.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-677 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-677 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-677`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- An adversary with access to hardware/software processes and tools within the development or hardware/software support environment can insert malicious software into hardware components during development or update/maintenance.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Execute Unauthorized Commands

## Mitigations to bypass

- Purchase IT systems, components and parts from government approved vendors whenever possible.
- Establish diversity among suppliers.
- Conduct rigorous threat assessments of suppliers.
- Require that Bills of Material (BoM) for critical parts and components be certified.
- Utilize contract language requiring contractors and subcontractors to flow down to subcontractors and suppliers SCRM and SCRA (Supply Chain Risk Assessment) requirements.
- Establish trusted supplier networks.

## Example instances (payload / topology hints)

- Malware is inserted into the Unified Extensible Firmware Interface (UEFI) software that resides on a flash memory chip soldered to a computer’s motherboard. It is the first thing to turn on when a system is booted and is allowed access to almost every part of the operating system. Hence, the malware will have extensive control over operating system functions and persist after system reboots. [REF…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-534](CAPEC-534.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-677 and CWE IDs
