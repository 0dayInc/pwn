# CAPEC-11: Cause Web Server Misclassification

- Catalog: [CAPEC-11](https://capec.mitre.org/data/definitions/11.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attack of this type exploits a Web server's decision to take action based on filename or file extension. Because different file types are handled by different server processes, misclassification may force the Web server to take unexpected action, or expected actions in an unexpected sequence. This may cause the server to exhaust resources, supply debug or system data to the attacker, or bind an attacker to a remote process.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-11 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-11 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-11`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Footprint file input vectors] Manually or using an automated tool, an attacker searches for all input locations where a user has control over the filenames or MIME types of files submitted to the web server. | techniques: Attacker manually crawls application to identify file inputs; Attacker uses an automated tool to crawl application identify file inputs; Attacker manually ass…
- Step 2 (Experiment): [File misclassification shotgunning] An attacker makes changes to file extensions and MIME types typically processed by web servers and looks for abnormal behavior. | techniques: Attacker submits files with switched extensions (e.g. .php on a .jsp file) to web server.; Attacker adds extra characters (e.g. adding an extra . after the file extension) to filenames of files submi…
- Step 3 (Experiment): [File misclassification sniping] Understanding how certain file types are processed by web servers, an attacker crafts varying file payloads and modifies their file extension or MIME type to be that of the targeted type to see if the web server is vulnerable to misclassification of that type. | techniques: Craft a malicious file payload, modify file extension to the targeted…
- Step 4 (Exploit): [Disclose information] The attacker, by manipulating a file extension or MIME type is able to make the web server return raw information (not executed). | techniques: Manipulate the file names that are explicitly sent to the server.; Manipulate the MIME sent in order to confuse the web server.

## Prerequisites

- Web server software must rely on file name or file extension for processing.
- The attacker must be able to make HTTP requests to the web server.

## Skills required

- Low: To modify file name or file extension
- Medium: To use misclassification to force the Web server to disclose configuration information, source, or binary data

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Implementation: Server routines should be determined by content not determined by filename or file extension.

## Example instances (payload / topology hints)

- J2EE application servers are supposed to execute Java Server Pages (JSP). There have been disclosure issues relating to Orion Application Server, where an attacker that appends either a period (.) or space characters to the end of a legitimate Http request, then the server displays the full source code in the attackers' web browser. http://victim.site/login.jsp. Since remote data and directory ac…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-635](CAPEC-635.md)

## Related CWEs (run the cwe skill)

- [CWE-430](../cwe/references/CWE-430.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-11 and CWE IDs
