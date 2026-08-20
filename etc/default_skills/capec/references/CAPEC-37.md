# CAPEC-37: Retrieve Embedded Sensitive Data

- Catalog: [CAPEC-37](https://capec.mitre.org/data/definitions/37.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An attacker examines a target system to find sensitive data that has been embedded within it. This information can reveal confidential contents, such as account numbers or individual keys/credentials that can be used as an intermediate step in a larger attack.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-37 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-37 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-37`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify Target] Attacker identifies client components to extract information from. These may be binary executables, class files, shared libraries (e.g., DLLs), configuration files, or other system files. | techniques: Binary file extraction. The attacker extracts binary files from zips, jars, wars, PDFs or other composite formats.; Package listing. The attacker uses a package…
- Step 2 (Exploit): [Retrieve Embedded Data] The attacker then uses a variety of techniques, such as sniffing, reverse-engineering, and cryptanalysis to retrieve the information of interest. | techniques: API Profiling. The attacker monitors the software's use of registry keys or other operating system-provided storage locations that can contain sensitive information.; Execution in simulator. The a…

## Prerequisites

- In order to feasibly execute this type of attack, some valuable data must be present in client software.
- Additionally, this information must be unprotected, or protected in a flawed fashion, or through a mechanism that fails to resist reverse engineering, statistical, or other attack.

## Skills required

- Medium: The attacker must possess knowledge of client code structure as well as ability to reverse-engineer or decompile it or probe it in other ways. This knowledge is specific to the technology and language used for the client distribution

## Resources required

- The attacker must possess access to the system or code being exploited. Such access, for this set of attacks, will likely be physical. The attacker will make use of reverse engineering technologies, perhaps for data or to extract functionality from the binary. Such tool use may be as simple as "Strings" or a hex editor. Removing functionality may require the use of only a hex editor, or may requi…

## Oracles (consequences)

- Confidentiality: Read Data
- Integrity: Modify Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- Using a tool such as 'strings' or similar to pull out text data, perhaps part of a database table, that extends beyond what a particular user's purview should be.
- An attacker can also use a decompiler to decompile a downloaded Java applet in order to look for information such as hardcoded IP addresses, file paths, passwords or other such contents.
- Attacker uses a tool such as a browser plug-in to pull cookie or other token information that, from a previous user at the same machine (perhaps a kiosk), allows the attacker to log in as the previous user.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-167](CAPEC-167.md)

## Related CWEs (run the cwe skill)

- [CWE-226](../cwe/references/CWE-226.md) — run that CWE procedure after this CAPEC flow
- [CWE-311](../cwe/references/CWE-311.md) — run that CWE procedure after this CAPEC flow
- [CWE-525](../cwe/references/CWE-525.md) — run that CWE procedure after this CAPEC flow
- [CWE-312](../cwe/references/CWE-312.md) — run that CWE procedure after this CAPEC flow
- [CWE-314](../cwe/references/CWE-314.md) — run that CWE procedure after this CAPEC flow
- [CWE-315](../cwe/references/CWE-315.md) — run that CWE procedure after this CAPEC flow
- [CWE-318](../cwe/references/CWE-318.md) — run that CWE procedure after this CAPEC flow
- [CWE-1239](../cwe/references/CWE-1239.md) — run that CWE procedure after this CAPEC flow
- [CWE-1258](../cwe/references/CWE-1258.md) — run that CWE procedure after this CAPEC flow
- [CWE-1266](../cwe/references/CWE-1266.md) — run that CWE procedure after this CAPEC flow
- [CWE-1272](../cwe/references/CWE-1272.md) — run that CWE procedure after this CAPEC flow
- [CWE-1278](../cwe/references/CWE-1278.md) — run that CWE procedure after this CAPEC flow
- [CWE-1301](../cwe/references/CWE-1301.md) — run that CWE procedure after this CAPEC flow
- [CWE-1330](../cwe/references/CWE-1330.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-37 and CWE IDs
