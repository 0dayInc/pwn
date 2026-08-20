# CAPEC-591: Reflected XSS

- Catalog: [CAPEC-591](https://capec.mitre.org/data/definitions/591.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

This type of attack is a form of Cross-Site Scripting (XSS) where a malicious script is "reflected" off a vulnerable web application and then executed by a victim's browser. The process starts with an adversary delivering a malicious script to a victim and convincing the victim to send the script to the vulnerable web application.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-591 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser, PWN::Plugins::Zaproxy

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-591 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-591`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for user-controllable inputs] Using a browser or an automated tool, an adversary follows all public links and actions on a web site. They record all the links, the forms, the resources accessed and all other potential entry-points for the web application. | techniques: Use a spidering tool to follow and record all links and analyze the web pages to find e…
- Step 2 (Experiment): [Probe identified potential entry points for reflected XSS vulnerability] The adversary uses the entry points gathered in the "Explore" phase as a target list and injects various common script payloads and special characters to determine if an entry point actually represents a vulnerability and to characterize the extent to which the vulnerability can be exploited. | techniqu…
- Step 3 (Experiment): [Craft malicious XSS URL] Once the adversary has determined which parameters are vulnerable to XSS, they will craft a malicious URL containing the XSS exploit. The adversary can have many goals, from stealing session IDs, cookies, credentials, and page content from the victim. | techniques: Change a URL parameter to include a malicious script tag.; Send information gathered f…
- Step 4 (Exploit): [Get victim to click URL] In order for the attack to be successful, the victim needs to access the malicious URL. | techniques: Send a phishing email to the victim containing the malicious URL. This can be hidden in a hyperlink as to not show the full URL, which might draw suspicion.; Put the malicious URL on a public forum, where many victims might accidentally click the link.

## Prerequisites

- An application that leverages a client-side web browser with scripting enabled.
- An application that fail to adequately sanitize or encode untrusted input.

## Skills required

- Medium: Requires the ability to write malicious scripts and embed them into HTTP requests.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality: Read Data — A successful Reflected XSS attack can enable an adversary to exfiltrate sensitive information from the application.
- Confidentiality, Authorization, Access Control: Gain Privileges — A successful Reflected XSS attack can enable an adversary to elevate their privilege level and access functionality they should not otherwise be allowed to access.
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — A successful Reflected attack can enable an adversary run arbitrary code of their choosing, thus enabling a complete compromise of the application.
- Integrity: Modify Data — A successful Reflected attack can allow an adversary to tamper with application data.

## Mitigations to bypass

- Use browser technologies that do not allow client-side scripting.
- Utilize strict type, character, and encoding enforcement.
- Ensure that all user-supplied input is validated before use.

## Example instances (payload / topology hints)

- Consider a web application that enables or disables some of the fields of a form on the page via the use of a mode parameter provided on the query string. http://my.site.com/aform.html?mode=full The application’s server-side code may want to display this mode value in the HTML page being created to give the users an understanding of what mode they are in. In this example, PHP is used to pull the…
- Reflected XSS attacks can take advantage of HTTP headers to compromise a victim. For example, assume a vulnerable web application called ‘mysite’ dynamically generates a link using an HTTP header such as HTTP_REFERER. Code somewhere in the application could look like: <?php echo "<a href="$_SERVER['HTTP_REFERER']">Test URL</a>" ?> The HTTP_REFERER header is populated with the URI that linked to t…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-63](CAPEC-63.md)

## Related CWEs (run the cwe skill)

- [CWE-79](../cwe/references/CWE-79.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-591 and CWE IDs
