# CAPEC-132: Symlink Attack

- Catalog: [CAPEC-132](https://capec.mitre.org/data/definitions/132.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary positions a symbolic link in such a manner that the targeted user or application accesses the link's endpoint, assuming that it is accessing a file with the link's name.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-132 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-132 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-132`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify Target] Adversary identifies the target application by determining whether there is sufficient check before writing data to a file and creating symlinks to files in different directories. | techniques: The adversary writes to files in different directories to check whether the application has sufficient checking before file operations.; The adversary creates symlinks t…
- Step 2 (Experiment): [Try to create symlinks to different files] The adversary then uses a variety of techniques, such as monitoring or guessing to create symlinks to the files accessed by the target application in the directories which are identified in the explore phase. | techniques: The adversary monitors the file operations performed by the target application using a tool like dtrace or File…
- Step 3 (Exploit): [Target application operates on created symlinks to sensitive files] The adversary is able to create symlinks to sensitive files while the target application is operating on the file. | techniques: Create the symlink to the sensitive file such as configuration files, etc.

## Prerequisites

- The targeted application must perform the desired activities on a file without checking whether the file is a symbolic link or not. The adversary must be able to predict the name of the file the target application is modifying and be able to create a new symbolic link where that file would appear.

## Skills required

- Low: To create symlinks
- High: To identify the files and create the symlinks during the file operation time window

## Resources required

- None: No specialized resources are required to execute this type of attack. The only requirement is the ability to create the necessary symbolic link.

## Oracles (consequences)

- Confidentiality: Other — Information Leakage
- Integrity: Modify Data
- Confidentiality: Read Data
- Integrity: Modify Data
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism
- Availability: Unreliable Execution

## Mitigations to bypass

- Design: Check for the existence of files to be created, if in existence verify they are neither symlinks nor hard links before opening them.
- Implementation: Use randomly generated file names for temporary files. Give the files restrictive permissions.

## Example instances (payload / topology hints)

- The adversary creates a symlink with the "same" name as the file which the application is intending to write to. The application will write to the file- "causing the data to be written where the symlink is pointing". An attack like this can be demonstrated as follows: root# vulprog myFile {...program does some processing...] adversary# ln –s /etc/nologin myFile [...program writes to 'myFile', whi…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-159](CAPEC-159.md)

## Related CWEs (run the cwe skill)

- [CWE-59](../cwe/references/CWE-59.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-132 and CWE IDs
