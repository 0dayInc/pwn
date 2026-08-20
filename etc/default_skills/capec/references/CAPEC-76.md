# CAPEC-76: Manipulating Web Input to File System Calls

- Catalog: [CAPEC-76](https://capec.mitre.org/data/definitions/76.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An attacker manipulates inputs to the target software which the target software passes to file system calls in the OS. The goal is to gain access to, and perhaps modify, areas of the file system that the target software did not intend to be accessible.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-76 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-76 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-76`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Fingerprinting of the operating system] In order to create a valid file injection, the attacker needs to know what the underlying OS is so that the proper file seperator is used. | techniques: Port mapping. Identify ports that the system is listening on, and attempt to identify inputs and protocol types on those ports.; TCP/IP Fingerprinting. The attacker uses various software…
- Step 2 (Explore): [Survey the Application to Identify User-controllable Inputs] The attacker surveys the target application to identify all user-controllable inputs, possibly as a valid and authenticated user | techniques: Spider web sites for all available links, entry points to the web site.; Manually explore application and inventory all application inputs
- Step 3 (Experiment): [Vary inputs, looking for malicious results] Depending on whether the application being exploited is a remote or local one, the attacker crafts the appropriate malicious input containing the path of the targeted file or other file system control syntax to be passed to the application | techniques: Inject context-appropriate malicious file path using network packet injection t…
- Step 4 (Exploit): [Manipulate files accessible by the application] The attacker may steal information or directly manipulate files (delete, copy, flush, etc.) | techniques: The attacker injects context-appropriate malicious file path to access the content of the targeted file.; The attacker injects context-appropriate malicious file system control syntax to access the content of the targeted file…

## Prerequisites

- Program must allow for user controlled variables to be applied directly to the filesystem

## Skills required

- Low: To identify file system entry point and execute against an over-privileged system interface

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Integrity: Modify Data

## Mitigations to bypass

- Design: Enforce principle of least privilege.
- Design: Ensure all input is validated, and does not contain file system commands
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.
- Design: For interactive user applications, consider if direct file system interface is necessary, instead consider having the application proxy communication.
- Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

## Example instances (payload / topology hints)

- The attacker uses relative path traversal to access files in the application. This is an example of accessing user's password file. http://www.example.com/getProfile.jsp?filename=../../../../etc/passwd However, the target application employs regular expressions to make sure no relative path sequences are being passed through the application to the web page. The application would replace all match…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-126](CAPEC-126.md)

## Related CWEs (run the cwe skill)

- [CWE-23](../cwe/references/CWE-23.md) — run that CWE procedure after this CAPEC flow
- [CWE-22](../cwe/references/CWE-22.md) — run that CWE procedure after this CAPEC flow
- [CWE-73](../cwe/references/CWE-73.md) — run that CWE procedure after this CAPEC flow
- [CWE-77](../cwe/references/CWE-77.md) — run that CWE procedure after this CAPEC flow
- [CWE-346](../cwe/references/CWE-346.md) — run that CWE procedure after this CAPEC flow
- [CWE-348](../cwe/references/CWE-348.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-272](../cwe/references/CWE-272.md) — run that CWE procedure after this CAPEC flow
- [CWE-59](../cwe/references/CWE-59.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-15](../cwe/references/CWE-15.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-76 and CWE IDs
