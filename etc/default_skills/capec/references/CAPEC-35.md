# CAPEC-35: Leverage Executable Code in Non-Executable Files

- Catalog: [CAPEC-35](https://capec.mitre.org/data/definitions/35.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An attack of this type exploits a system's trust in configuration and resource files. When the executable loads the resource (such as an image file or configuration file) the attacker has modified the file to either execute malicious code directly or manipulate the target process (e.g. application server) to execute based on the malicious configuration parameters. Since systems are increasingly interrelated mashing up resources from local and remote sources the possibility of this attack occurring is high.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-35 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-35 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-35`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The attacker must have the ability to modify non-executable files consumed by the target software.

## Skills required

- Low: To identify and execute against an over-privileged system interface

## Resources required

- Ability to communicate synchronously or asynchronously with server that publishes an over-privileged directory, program, or interface. Optionally, ability to capture output directly through synchronous communication or other method such as FTP.

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Integrity: Modify Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Design: Enforce principle of least privilege
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.
- Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.
- Implementation: Implement host integrity monitoring to detect any unwanted altering of configuration files.
- Implementation: Ensure that files that are not required to execute, such as configuration files, are not over-privileged, i.e. not allowed to execute.

## Example instances (payload / topology hints)

- Virtually any system that relies on configuration files for runtime behavior is open to this attack vector. The configuration files are frequently stored in predictable locations, so an attacker that can fingerprint a server process such as a web server or database server can quickly identify the likely locale where the configuration is stored. And this is of course not limited to server processe…
- The attack can be directed at a client system, such as causing buffer overrun through loading seemingly benign image files, as in Microsoft Security Bulletin MS04-028 where specially crafted JPEG files could cause a buffer overrun once loaded into the browser.
- Another example targets clients reading pdf files. In this case the attacker simply appends javascript to the end of a legitimate url for a pdf (http://www.gnucitizen.org/blog/danger-danger-danger/) http://path/to/pdf/file.pdf#whatever_name_you_want=javascript:your_code_here The client assumes that they are reading a pdf, but the attacker has modified the resource and loaded executable javascript…
- The attack can also target server processes. The attacker edits the resource or configuration file, for example a web.xml file used to configure security permissions for a J2EE app server, adding role name "public" grants all users with the public role the ability to use the administration functionality. < security-constraint> <description>Security processing rules for admin screens</description>…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-636](CAPEC-636.md)
- PeerOf → [CAPEC-23](CAPEC-23.md)
- PeerOf → [CAPEC-75](CAPEC-75.md)

## Related CWEs (run the cwe skill)

- [CWE-94](../cwe/references/CWE-94.md) — run that CWE procedure after this CAPEC flow
- [CWE-96](../cwe/references/CWE-96.md) — run that CWE procedure after this CAPEC flow
- [CWE-95](../cwe/references/CWE-95.md) — run that CWE procedure after this CAPEC flow
- [CWE-97](../cwe/references/CWE-97.md) — run that CWE procedure after this CAPEC flow
- [CWE-272](../cwe/references/CWE-272.md) — run that CWE procedure after this CAPEC flow
- [CWE-59](../cwe/references/CWE-59.md) — run that CWE procedure after this CAPEC flow
- [CWE-282](../cwe/references/CWE-282.md) — run that CWE procedure after this CAPEC flow
- [CWE-270](../cwe/references/CWE-270.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-35 and CWE IDs
