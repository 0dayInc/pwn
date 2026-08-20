# CAPEC-52: Embedding NULL Bytes

- Catalog: [CAPEC-52](https://capec.mitre.org/data/definitions/52.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary embeds one or more null bytes in input to the target software. This attack relies on the usage of a null-valued byte as a string terminator in many environments. The goal is for certain components of the target software to stop processing the input when it encounters the null byte(s).

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-52 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-52 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-52`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for user-controllable inputs] Using a browser, an automated tool or by inspecting the application, an adversary records all entry points to the application. | techniques: Use a spidering tool to follow and record all links and analyze the web pages to find entry points. Make special note of any links that include parameters in the URL.; Use a proxy tool t…
- Step 2 (Experiment): [Probe entry points to locate vulnerabilities] The adversary uses the entry points gathered in the "Explore" phase as a target list and injects postfix null byte(s) to observe how the application handles them as input. The adversary is looking for areas where user input is placed in the middle of a string, and the null byte causes the application to stop processing the string…
- Step 3 (Exploit): [Remove data after null byte(s)] After determined entry points that are vulnerable, the adversary places a null byte(s) such that they remove data after the null byte(s) in a way that is beneficial to them. | techniques: If the input is a directory as part of a longer file path, add a null byte(s) at the end of the input to try to traverse to the given directory.

## Prerequisites

- The program does not properly handle postfix NULL terminators

## Skills required

- Medium: Directory traversal
- High: Execution of arbitrary code

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Properly handle the NULL characters supplied as part of user input prior to doing anything with the data.

## Example instances (payload / topology hints)

- Directory Browsing Assume a Web application allows a user to access a set of reports. The path to the reports directory may be something like web/username/reports. If the username is supplied via a hidden field, an adversary could insert a bogus username such as ../../../../../WINDOWS. If the adversary needs to remove the trailing string /reports, then they can simply insert enough characters so…
- Exploitation of a buffer overflow vulnerability in the ActiveX component packaged with Adobe Systems Inc.'s Acrobat/Acrobat Reader allows remote adversaries to execute arbitrary code. The problem specifically exists upon retrieving a link of the following form: GET /any_existing_dir/any_existing_pdf.pdf%00[long string] HTTP/1.1 Where [long string] is a malicious crafted long string containing acc…
- Consider the following PHP script: $whatever = addslashes($_REQUEST['whatever']); include("/path/to/program/" . $whatever . "/header.htm"); A malicious adversary might open the following URL, disclosing the boot.ini file: http://localhost/phpscript.php?whatever=../../../../boot.ini%00

## Related CAPECs (test these too)

- ChildOf → [CAPEC-267](CAPEC-267.md)

## Related CWEs (run the cwe skill)

- [CWE-158](../cwe/references/CWE-158.md) — run that CWE procedure after this CAPEC flow
- [CWE-172](../cwe/references/CWE-172.md) — run that CWE procedure after this CAPEC flow
- [CWE-173](../cwe/references/CWE-173.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow
- [CWE-707](../cwe/references/CWE-707.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-52 and CWE IDs
