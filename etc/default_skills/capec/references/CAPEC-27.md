# CAPEC-27: Leveraging Race Conditions via Symbolic Links

- Catalog: [CAPEC-27](https://capec.mitre.org/data/definitions/27.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack leverages the use of symbolic links (Symlinks) in order to write to sensitive files. An attacker can create a Symlink link to a target file not otherwise accessible to them. When the privileged program tries to create a temporary file with the same name as the Symlink link, it will actually write to the target file pointed to by the attackers' Symlink link. If the attacker can insert malicious content in the temporary file they will be writing to the sensitive file by using the Symlink. The race occurs because the system checks if the temporary file exists, then creates the file. The attacker would typically create the Symlink during the interval between the check and the creation of the temporary file.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-27 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-27 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-27`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Verify that target host's platform supports symbolic links.] This attack pattern is only applicable on platforms that support symbolic links. | techniques: Research target platform to determine whether it supports symbolic links.; Create a symbolic link and ensure that it works as expected on the given platform.
- Step 2 (Explore): [Examine application's file I/O behavior] Analyze the application's file I/O behavior to determine where it stores files, as well as the operations it performs to read/write files. | techniques: Use kernel tracing utility such as ktrace to monitor application behavior.; Use debugging utility such as File Monitor to monitor the application's filesystem I/O calls; Watch temporary…
- Step 3 (Experiment): [Verify ability to write to filesystem] The attacker verifies ability to write to the target host's file system. | techniques: Create a file that does not exist in the target directory (e.g. "touch temp.txt" in UNIX-like systems); On platforms that differentiate between file creation and file modification, if the target file that the application writes to already exists, atte…
- Step 4 (Exploit): [Replace file with a symlink to a sensitive system file.] Between the time that the application checks to see if a file exists (or if the user has access to it) and the time the application actually opens the file, the attacker replaces the file with a symlink to a sensitive system file. | techniques: Create an infinite loop containing commands such as "rm -f tempfile.dat; ln -s…

## Prerequisites

- The attacker is able to create Symlink links on the target host.
- Tainted data from the attacker is used and copied to temporary files.
- The target host does insecure temporary file creation.

## Skills required

- Medium: This attack is sophisticated because the attacker has to overcome a few challenges such as creating symlinks on the target host during a precise timing, inserting malicious data in the temporary file and have knowledge about the temporary files created (file name and function which creates them).

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Availability: Resource Consumption — Denial of Service

## Mitigations to bypass

- Use safe libraries when creating temporary files. For instance the standard library function mkstemp can be used to safely create temporary files. For shell scripts, the system utility mktemp does the same thing.
- Access to the directories should be restricted as to prevent attackers from manipulating the files. Denying access to a file can prevent an attacker from replacing that file with a link to a sensitive file.
- Follow the principle of least privilege when assigning access rights to files.
- Ensure good compartmentalization in the system to provide protected areas that can be trusted.

## Example instances (payload / topology hints)

- In this naive example, the Unix program foo is setuid. Its function is to retrieve information for the accounts specified by the user. For "efficiency," it sorts the requested accounts into a temporary file (/tmp/foo naturally) before making the queries. The directory /tmp is world-writable. The malicious user creates a symbolic link to the file /.rhosts named /tmp/foo. Then, they invokes foo wit…
- GNU "ed" utility (before 0.3) allows local users to overwrite arbitrary files via a symlink attack on temporary files, possibly in the open_sbuf function. See also: CVE-2006-6939
- OpenmosixCollector and OpenMosixView in OpenMosixView 1.5 allow local users to overwrite or delete arbitrary files via a symlink attack on (1) temporary files in the openmosixcollector directory or (2) nodes.tmp. See also: CVE-2005-0894
- Setuid product allows file reading by replacing a file being edited with a symlink to the targeted file, leaking the result in error messages when parsing fails. See also: CVE-2000-0972

## Related CAPECs (test these too)

- ChildOf → [CAPEC-29](CAPEC-29.md)

## Related CWEs (run the cwe skill)

- [CWE-367](../cwe/references/CWE-367.md) — run that CWE procedure after this CAPEC flow
- [CWE-61](../cwe/references/CWE-61.md) — run that CWE procedure after this CAPEC flow
- [CWE-662](../cwe/references/CWE-662.md) — run that CWE procedure after this CAPEC flow
- [CWE-689](../cwe/references/CWE-689.md) — run that CWE procedure after this CAPEC flow
- [CWE-667](../cwe/references/CWE-667.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-27 and CWE IDs
