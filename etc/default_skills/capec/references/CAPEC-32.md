# CAPEC-32: XSS Through HTTP Query Strings

- Catalog: [CAPEC-32](https://capec.mitre.org/data/definitions/32.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary embeds malicious script code in the parameters of an HTTP query string and convinces a victim to submit the HTTP request that contains the query string to a vulnerable web application. The web application then procedes to use the values parameters without properly validation them first and generates the HTML code that will be executed by the victim's browser.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-32 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser, PWN::Plugins::Zaproxy

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-32 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-32`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for public links] Using a browser or an automated tool, an adversary follows all public links on a web site. They record all the links they find. | techniques: Use a spidering tool to follow and record all links. Make special note of any links that include parameters in the URL.; Use a proxy tool to record all links visited during a manual traversal of th…
- Step 2 (Experiment): [Probe public links for XSS vulnerability] The adversary uses the public links gathered in the "Explore" phase as a target list and requests variations on the URLs they spidered before. They send parameters that include variations of payloads. They record all the responses from the server that include unmodified versions of their script. | techniques: Use a list of XSS probe…
- Step 3 (Experiment): [Craft malicious XSS URL] Once the adversary has determined which parameters are vulnerable to XSS, they will craft a malicious URL containing the XSS exploit. The adversary can have many goals, from stealing session IDs, cookies, credentials, and page content from the victim. | techniques: Change a URL parameter to include a malicious script tag.; Send information gathered f…
- Step 4 (Exploit): [Get victim to click URL] In order for the attack to be successful, the victim needs to access the malicious URL. | techniques: Send a phishing email to the victim containing the malicious URL. This can be hidden in a hyperlink as to not show the full URL, which might draw suspicion.; Put the malicious URL on a public forum, where many victims might accidentally click the link.

## Prerequisites

- Target client software must allow scripting such as JavaScript. Server software must allow display of remote generated HTML without sufficient input or output validation.

## Skills required

- Low: To place malicious payload on server via HTTP
- High: Exploiting any information gathered by HTTP Query on script host

## Resources required

- Ability to send HTTP post to scripting host and collect output

## Oracles (consequences)

- Confidentiality: Read Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Design: Use browser technologies that do not allow client side scripting.
- Design: Utilize strict type, character, and encoding enforcement
- Design: Server side developers should not proxy content via XHR or other means, if a http proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Perform input validation for all remote content, including remote and user-generated content
- Implementation: Perform output validation for all remote content.
- Implementation: Disable scripting languages such as JavaScript in browser
- Implementation: Session tokens for specific host
- Implementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.
- Implementation: Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

## Example instances (payload / topology hints)

- http://user:host@example.com:8080/oradb<script>alert('Hi')</script>
- Web applications that accept name value pairs in a HTTP Query string are inherently at risk to any value (or name for that matter) that an adversary would like to enter in the query string. This can be done manually via web browser or trivially scripted to post the query string to multiple sites. In the latter case, in the instance of many sites using similar infrastructure with predictable http…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-591](CAPEC-591.md)
- ChildOf → [CAPEC-588](CAPEC-588.md)
- ChildOf → [CAPEC-592](CAPEC-592.md)

## Related CWEs (run the cwe skill)

- [CWE-80](../cwe/references/CWE-80.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-32 and CWE IDs
