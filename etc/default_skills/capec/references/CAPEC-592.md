# CAPEC-592: Stored XSS

- Catalog: [CAPEC-592](https://capec.mitre.org/data/definitions/592.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary utilizes a form of Cross-site Scripting (XSS) where a malicious script is persistently "stored" within the data storage of a vulnerable web application as valid input.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-592 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser, PWN::Plugins::Zaproxy

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-592 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-592`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for stored user-controllable inputs] Using a browser or an automated tool, an adversary follows all public links and actions on a web site. They record all the links, the forms, the resources accessed and all other potential entry-points for the web application. The adversary is looking for areas where user input is stored, such as user profiles, shopping…
- Step 2 (Experiment): [Probe identified potential entry points for stored XSS vulnerability] The adversary uses the entry points gathered in the "Explore" phase as a target list and injects various common script payloads and special characters to determine if an entry point actually represents a vulnerability and to characterize the extent to which the vulnerability can be exploited. | techniques:…
- Step 3 (Experiment): [Store malicious XSS content] Once the adversary has determined which stored locations are vulnerable to XSS, they will interact with the web application to store the malicious content. The adversary can have many goals, from stealing session IDs, cookies, credentials, and page content from a victim. | techniques: Store a malicious script on a page that will execute when view…
- Step 4 (Exploit): [Get victim to view stored content] In order for the attack to be successful, the victim needs to view the stored malicious content on the webpage. | techniques: Send a phishing email to the victim containing a URL that will direct them to the malicious stored content.; Simply wait for a victim to view the content. This is viable in situations where content is posted to a popula…

## Prerequisites

- An application that leverages a client-side web browser with scripting enabled.
- An application that fails to adequately sanitize or encode untrusted input.
- An application that stores information provided by the user in data storage of some kind.

## Skills required

- Medium: Requires the ability to write scripts of varying complexity and to inject them through user controlled fields within the application.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality: Read Data — A successful Stored XSS attack can enable an adversary to exfiltrate sensitive information from the application.
- Confidentiality, Authorization, Access Control: Gain Privileges — A successful Stored XSS attack can enable an adversary to elevate their privilege level and access functionality they should not otherwise be allowed to access.
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — A successful Stored XSS attack can enable an adversary run arbitrary code of their choosing, thus enabling a complete compromise of the application.
- Integrity: Modify Data — A successful Stored XSS attack can allow an adversary to tamper with application data.

## Mitigations to bypass

- Use browser technologies that do not allow client-side scripting.
- Utilize strict type, character, and encoding enforcement.
- Ensure that all user-supplied input is validated before being stored.

## Example instances (payload / topology hints)

- An adversary determines that a system uses a web based interface for administration. The adversary creates a new user record and supplies a malicious script in the user name field. The user name field is not validated by the system and a new log entry is created detailing the creation of the new user. Later, an administrator reviews the log in the administrative console. When the administrator co…
- An online discussion forum allows its members to post HTML-enabled messages, which can also include image tags. An adversary embeds JavaScript in the image tags of their message. The adversary then sends the victim an email advertising free goods and provides a link to the form for how to collect. When the victim visits the forum and reads the message, the malicious script is executed within the…

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
- [ ] Finding (if any) cites CAPEC-592 and CWE IDs
