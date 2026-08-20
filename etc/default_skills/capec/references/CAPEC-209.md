# CAPEC-209: XSS Using MIME Type Mismatch

- Catalog: [CAPEC-209](https://capec.mitre.org/data/definitions/209.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary creates a file with scripting content but where the specified MIME type of the file is such that scripting is not expected. The adversary tricks the victim into accessing a URL that responds with the script file. Some browsers will detect that the specified MIME type of the file does not match the actual type of its content and will automatically switch to using an interpreter for the real content type. If the browser does not invoke script filters before doing this, the adversary's script may run on the target unsanitized, possibly revealing the victim's cookies or executing arbitrary script in their browser.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-209 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser, PWN::Plugins::Zaproxy; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-209 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-209`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for stored user-controllable inputs] Using a browser or an automated tool, an adversary follows all public links and actions on a web site. They record all areas that allow a user to upload content through an HTTP POST request. This is typically found in blogs or forums. | techniques: Use a spidering tool to follow and record all links and analyze the web…
- Step 2 (Experiment): [Probe identified potential entry points for MIME type mismatch] The adversary uses the entry points gathered in the "Explore" phase as a target list and uploads files with scripting content, but whose MIME type is specified as a file type that cannot execute scripting content. If the application only checks the MIME type of the file, it may let the file through, causing the…
- Step 3 (Experiment): [Store malicious XSS content] Once the adversary has determined which file upload locations are vulnerable to MIME type mismatch, they will upload a malicious script disguised as a non scripting file. The adversary can have many goals, from stealing session IDs, cookies, credentials, and page content from a victim. | techniques: Use a tool such as BeEF to store a hook into th…
- Step 4 (Exploit): [Get victim to view stored content] In order for the attack to be successful, the victim needs to view the stored malicious content on the webpage. | techniques: Send a phishing email to the victim containing a URL that will direct them to the malicious stored content.; Simply wait for a victim to view the content. This is viable in situations where content is posted to a popula…

## Prerequisites

- The victim must follow a crafted link that references a scripting file that is mis-typed as a non-executable file.
- The victim's browser must detect the true type of a mis-labeled scripting file and invoke the appropriate script interpreter without first performing filtering on the content.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- The adversary must have the ability to source the file of the incorrect MIME type containing a script.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- For example, the MIME type text/plain may be used where the actual content is text/javascript or text/html. Since text does not contain scripting instructions, the stated MIME type would indicate that filtering is unnecessary. However, if the target application subsequently determines the file's real type and invokes the appropriate interpreter, scripted content could be invoked.
- In another example, img tags in HTML content could reference a renderable type file instead of an expected image file. The file extension and MIME type can describe an image file, but the file content can be text/javascript or text/html resulting in script execution. If the browser assumes all references in img tags are images, and therefore do not need to be filtered for scripts, this would bypa…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-592](CAPEC-592.md)

## Related CWEs (run the cwe skill)

- [CWE-79](../cwe/references/CWE-79.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-646](../cwe/references/CWE-646.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-209 and CWE IDs
