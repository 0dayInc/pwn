# CAPEC-127: Directory Indexing

- Catalog: [CAPEC-127](https://capec.mitre.org/data/definitions/127.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary crafts a request to a target that results in the target listing/indexing the content of a directory as output. One common method of triggering directory contents as output is to construct a request containing a path that terminates in a directory name rather than a file name since many applications are configured to provide a list of the directory's contents when such a request is received. An adversary can use this to explore the directory tree on a target as well as learn the names of files. This can often end up revealing test files, backup files, temporary files, hidden files, configuration files, user accounts, script contents, as well as naming conventions, all of which can be used by an attacker to mount additional attacks.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-127 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-127 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-127`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Directory Discovery] Use a method, either manual, scripted, or automated to discover the directories on the server by making requests for directories that may possibly exist. During this phase the adversary is less concerned with whether a directory can be accessed or indexed and more focused on simply discovering what directories do exist on the target. | techniques: Send requ…
- Step 2 (Experiment): [Iteratively explore directory/file structures] The adversary attempts to access the discovered directories that allow access and may attempt to bypass server or application level ACLs by using manual or automated methods | techniques: Use a scanner tool to dynamically add directories/files to include their scan based upon data obtained in initial probes.; Use a browser to ma…
- Step 3 (Exploit): [Read directories or files which are not intended for public viewing.] The adversary attempts to access the discovered directories that allow access and may attempt to bypass server or application level ACLs by using manual or automated methods | techniques: Try multiple exploit techniques to list directory contents for directories that will not reveal their contents with a "/"…

## Prerequisites

- The target must be misconfigured to return a list of a directory's content when it receives a request that ends in a directory name rather than a file name.
- The adversary must be able to control the path that is requested of the target.
- The administrator must have failed to properly configure an ACL or has associated an overly permissive ACL with a particular directory.
- The server version or patch level must not inherently prevent known directory listing attacks from working.

## Skills required

- Low: To issue the request to URL without given a specific file name
- High: To bypass the access control of the directory of listings

## Resources required

- Ability to send HTTP requests to a web application.

## Oracles (consequences)

- Confidentiality: Read Data — Information Leakage

## Mitigations to bypass

- 1. Using blank index.html: putting blank index.html simply prevent directory listings from displaying to site visitors.
- 2. Preventing with .htaccess in Apache web server: In .htaccess, write "Options-indexes".
- 3. Suppressing error messages: using error 403 "Forbidden" message exactly like error 404 "Not Found" message.

## Example instances (payload / topology hints)

- The adversary uses directory listing to view sensitive files in the application. This is an example of accessing the backup file. The attack issues a request for http://www.example.com/admin/ and receives the following dynamic directory indexing content in the response: Index of /admin Name Last Modified Size Description backup/ 31-May-2007 08:18 - Apache/ 2.0.55 Server at www.example.com Port 80…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-54](CAPEC-54.md)

## Related CWEs (run the cwe skill)

- [CWE-424](../cwe/references/CWE-424.md) — run that CWE procedure after this CAPEC flow
- [CWE-425](../cwe/references/CWE-425.md) — run that CWE procedure after this CAPEC flow
- [CWE-288](../cwe/references/CWE-288.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-732](../cwe/references/CWE-732.md) — run that CWE procedure after this CAPEC flow
- [CWE-276](../cwe/references/CWE-276.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-127 and CWE IDs
