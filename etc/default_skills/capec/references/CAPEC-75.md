# CAPEC-75: Manipulating Writeable Configuration Files

- Catalog: [CAPEC-75](https://capec.mitre.org/data/definitions/75.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

Generally these are manually edited files that are not in the preview of the system administrators, any ability on the attackers' behalf to modify these files, for example in a CVS repository, gives unauthorized access directly to the application, the same as authorized users.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-75 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-75 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-75`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- Configuration files must be modifiable by the attacker

## Skills required

- Medium: To identify vulnerable configuration files, and understand how to manipulate servers and erase forensic evidence

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Design: Enforce principle of least privilege
- Design: Backup copies of all configuration files
- Implementation: Integrity monitoring for configuration files
- Implementation: Enforce audit logging on code and configuration promotion procedures.
- Implementation: Load configuration from separate process and memory space, for example a separate physical device like a CD

## Example instances (payload / topology hints)

- The BEA Weblogic server uses a config.xml file to store configuration data. If this file is not properly protected by the system access control, an attacker can write configuration information to redirect server output through system logs, database connections, malicious URLs and so on. Access to the Weblogic server may be from a so-called Custom realm which manages authentication and authorizati…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-176](CAPEC-176.md)

## Related CWEs (run the cwe skill)

- [CWE-349](../cwe/references/CWE-349.md) — run that CWE procedure after this CAPEC flow
- [CWE-99](../cwe/references/CWE-99.md) — run that CWE procedure after this CAPEC flow
- [CWE-77](../cwe/references/CWE-77.md) — run that CWE procedure after this CAPEC flow
- [CWE-346](../cwe/references/CWE-346.md) — run that CWE procedure after this CAPEC flow
- [CWE-353](../cwe/references/CWE-353.md) — run that CWE procedure after this CAPEC flow
- [CWE-354](../cwe/references/CWE-354.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-75 and CWE IDs
