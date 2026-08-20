# CAPEC-694: System Location Discovery

- Catalog: [CAPEC-694](https://capec.mitre.org/data/definitions/694.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: High · Typical severity: Very Low
- CAPEC list: 3.9

## Attack pattern

An adversary collects information about the target system in an attempt to identify the system's geographical location. Information gathered could include keyboard layout, system language, and timezone. This information may benefit an adversary in confirming the desired target and/or tailoring further attacks.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-694 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-694 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-694`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [System Locale Information Discovery] The adversary examines system information from various sources such as registry and native API functions and correlates the gathered information to infer the geographical location of the target system | techniques: Registry Query: Query the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ContentIndex\Language\Language_Dialec…

## Prerequisites

- The adversary must have some level of access to the system and have a basic understanding of the operating system in order to query the appropriate sources for relevant information.

## Skills required

- Low: The adversary must know how to query various system sources of information respective of the system's operating system to obtain the relevant information.

## Resources required

- The adversary requires access to the target's operating system tools to query relevant system information. On windows, registry queries can be conducted with powershell, wmi, or regedit. On Linux or macOS, queries can be performed with through a shell.

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- To reduce the amount of information gathered, one could disable various geolocation features of the operating system not required for system operation.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-169](CAPEC-169.md)

## Related CWEs (run the cwe skill)

- [CWE-497](../cwe/references/CWE-497.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-694 and CWE IDs
