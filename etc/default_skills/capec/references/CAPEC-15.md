# CAPEC-15: Command Delimiters

- Catalog: [CAPEC-15](https://capec.mitre.org/data/definitions/15.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attack of this type exploits a programs' vulnerabilities that allows an attacker's commands to be concatenated onto a legitimate command with the intent of targeting other resources such as the file system or database. The system that uses a filter or denylist input validation, as opposed to allowlist validation is vulnerable to an attacker who predicts delimiters (or combinations of delimiters) not present in the filter or denylist. As with other injection attacks, the attacker uses the command delimiter payload as an entry point to tunnel through the application and activate additional attacks through SQL queries, shell commands, network scanning, and so on.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-15 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-15 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-15`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Assess Target Runtime Environment] In situations where the runtime environment is not implicitly known, the attacker makes connections to the target system and tries to determine the system's runtime environment. Knowing the environment is vital to choosing the correct delimiters. | techniques: Port mapping using network connection-based software (e.g., nmap, nessus, etc.); Por…
- Step 2 (Explore): [Survey the Application] The attacker surveys the target application, possibly as a valid and authenticated user | techniques: Spidering web sites for all available links; Inventory all application inputs
- Step 3 (Experiment): [Attempt delimiters in inputs] The attacker systematically attempts variations of delimiters on known inputs, observing the application's response each time. | techniques: Inject command delimiters using network packet injection tools (netcat, nemesis, etc.); Inject command delimiters using web test frameworks (proxies, TamperData, custom programs, etc.); Enter command delimi…
- Step 4 (Exploit): [Use malicious command delimiters] The attacker uses combinations of payload and carefully placed command delimiters to attack the software.

## Prerequisites

- Software's input validation or filtering must not detect and block presence of additional malicious command.

## Skills required

- Medium: The attacker has to identify injection vector, identify the specific commands, and optionally collect the output, i.e. from an interactive session.

## Resources required

- Ability to communicate synchronously or asynchronously with server. Optionally, ability to capture output directly through synchronous communication or other method such as FTP.

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality: Read Data

## Mitigations to bypass

- Design: Perform allowlist validation against a positive specification for command length, type, and parameters.
- Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged account
- Implementation: Perform input validation for all remote content.
- Implementation: Use type conversions such as JDBC prepared statements.

## Example instances (payload / topology hints)

- By appending special characters, such as a semicolon or other commands that are executed by the target process, the attacker is able to execute a wide variety of malicious commands in the target process space, utilizing the target's inherited permissions, against any resource the host has access to. The possibilities are vast including injection attacks against RDBMS (SQL Injection), directory se…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-137](CAPEC-137.md)

## Related CWEs (run the cwe skill)

- [CWE-146](../cwe/references/CWE-146.md) — run that CWE procedure after this CAPEC flow
- [CWE-77](../cwe/references/CWE-77.md) — run that CWE procedure after this CAPEC flow
- [CWE-184](../cwe/references/CWE-184.md) — run that CWE procedure after this CAPEC flow
- [CWE-78](../cwe/references/CWE-78.md) — run that CWE procedure after this CAPEC flow
- [CWE-185](../cwe/references/CWE-185.md) — run that CWE procedure after this CAPEC flow
- [CWE-93](../cwe/references/CWE-93.md) — run that CWE procedure after this CAPEC flow
- [CWE-140](../cwe/references/CWE-140.md) — run that CWE procedure after this CAPEC flow
- [CWE-157](../cwe/references/CWE-157.md) — run that CWE procedure after this CAPEC flow
- [CWE-138](../cwe/references/CWE-138.md) — run that CWE procedure after this CAPEC flow
- [CWE-154](../cwe/references/CWE-154.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-15 and CWE IDs
