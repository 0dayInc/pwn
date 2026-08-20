# CAPEC-121: Exploit Non-Production Interfaces

- Catalog: [CAPEC-121](https://capec.mitre.org/data/definitions/121.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits a sample, demonstration, test, or debug interface that is unintentionally enabled on a production system, with the goal of gleaning information or leveraging functionality that would otherwise be unavailable.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-121 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-121 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-121`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine Vulnerable Interface] An adversary explores a target system for sample or test interfaces that have not been disabled by a system administrator and which may be exploitable by the adversary. | techniques: If needed, the adversary explores an organization's network to determine if any specific systems of interest exist.
- Step 2 (Exploit): [Leverage Test Interface to Execute Attacks] Once an adversary has discovered a system with a non-production interface, the interface is leveraged to exploit the system and/or conduct various attacks. | techniques: The adversary can leverage the sample or test interface to conduct several types of attacks such as Adversary-in-the-Middle attacks (CAPEC-94), keylogging, Cross Site…

## Prerequisites

- The target must have configured non-production interfaces and failed to secure or remove them when brought into a production environment.

## Skills required

- High: Exploiting non-production interfaces requires significant skill and knowledge about the potential non-production interfaces left enabled in production.

## Resources required

- For some interfaces, the adversary will need that appropriate client application or hardware that interfaces with the interface. Other non-production interfaces can be executed using simple tools, such as web browsers or console windows. In some cases, an adversary may need to be able to authenticate to the target before it can access the vulnerable interface.

## Oracles (consequences)

- Confidentiality, Access Control, Authentication: Gain Privileges, Bypass Protection Mechanism
- Confidentiality, Access Control, Authorization: Read Data, Execute Unauthorized Commands
- Access Control, Integrity: Modify Data, Alter Execution Logic

## Mitigations to bypass

- Ensure that production systems do not contain non-production interfaces and that these interfaces are only used in development environments.

## Example instances (payload / topology hints)

- Some software applications include application programming interfaces (APIs) that are intended to allow an administrator to test and refine their domain. These APIs are typically disabled once a system enters a production environment, but may be left in an insecure state due to a configuration error or mismanagement.
- Many hardware systems leverage bits typically reserved for future functionality for testing and debugging purposes. If these reserved bits remain enabled in a production environment, it could allow an adversary to induce unwanted/unsupported behavior in the hardware.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-113](CAPEC-113.md)

## Related CWEs (run the cwe skill)

- [CWE-489](../cwe/references/CWE-489.md) — run that CWE procedure after this CAPEC flow
- [CWE-1209](../cwe/references/CWE-1209.md) — run that CWE procedure after this CAPEC flow
- [CWE-1259](../cwe/references/CWE-1259.md) — run that CWE procedure after this CAPEC flow
- [CWE-1267](../cwe/references/CWE-1267.md) — run that CWE procedure after this CAPEC flow
- [CWE-1270](../cwe/references/CWE-1270.md) — run that CWE procedure after this CAPEC flow
- [CWE-1294](../cwe/references/CWE-1294.md) — run that CWE procedure after this CAPEC flow
- [CWE-1295](../cwe/references/CWE-1295.md) — run that CWE procedure after this CAPEC flow
- [CWE-1296](../cwe/references/CWE-1296.md) — run that CWE procedure after this CAPEC flow
- [CWE-1302](../cwe/references/CWE-1302.md) — run that CWE procedure after this CAPEC flow
- [CWE-1313](../cwe/references/CWE-1313.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-121 and CWE IDs
