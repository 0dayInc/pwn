# CAPEC-193: PHP Remote File Inclusion

- Catalog: [CAPEC-193](https://capec.mitre.org/data/definitions/193.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

In this pattern the adversary is able to load and execute arbitrary code remotely available from the application. This is usually accomplished through an insecurely configured PHP runtime environment and an improperly sanitized "include" or "require" call, which the user can then control to point to any web-accessible file. This allows adversaries to hijack the targeted application and force it to execute their own instructions.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-193 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-193 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-193`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey application] Using a browser or an automated tool, an adversary follows all public links on a web site. They record all the links they find. | techniques: Use a spidering tool to follow and record all links. Make special note of any links that include parameters in the URL.; Use a proxy tool to record all links visited during a manual traversal of the web application. Ma…
- Step 2 (Experiment): [Attempt variations on input parameters] The attack variants make use of a remotely available PHP script that generates a uniquely identifiable output when executed on the target application server. Possibly using an automated tool, an adversary requests variations on the inputs they surveyed before. They send parameters that include variations of payloads which include a ref…
- Step 3 (Exploit): [Run arbitrary server-side code] As the adversary succeeds in exploiting the vulnerability, they are able to execute server-side code within the application. The malicious code has virtual access to the same resources as the targeted application. Note that the adversary might include shell code in their script and execute commands on the server under the same privileges as the P…

## Prerequisites

- Target application server must allow remote files to be included in the "require", "include", etc. PHP directives
- The adversary must have the ability to make HTTP requests to the target web application.

## Skills required

- Low: To inject the malicious payload in a web page
- Medium: To bypass filters in the application

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Implementation: Perform input validation for all remote content, including remote and user-generated content
- Implementation: Only allow known files to be included (allowlist)
- Implementation: Make use of indirect references passed in URL parameters instead of file names
- Configuration: Ensure that remote scripts cannot be include in the "include" or "require" PHP directives

## Example instances (payload / topology hints)

- The adversary controls a PHP script on a server "http://attacker.com/rfi.txt" The .txt extension is given so that the script doesn't get executed by the attacker.com server, and it will be downloaded as text. The target application is vulnerable to PHP remote file inclusion as following: include($_GET['filename'] . '.txt') The adversary creates an HTTP request that passes their own script in the…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-253](CAPEC-253.md)

## Related CWEs (run the cwe skill)

- [CWE-98](../cwe/references/CWE-98.md) — run that CWE procedure after this CAPEC flow
- [CWE-80](../cwe/references/CWE-80.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-193 and CWE IDs
