# CAPEC-243: XSS Targeting HTML Attributes

- Catalog: [CAPEC-243](https://capec.mitre.org/data/definitions/243.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary inserts commands to perform cross-site scripting (XSS) actions in HTML attributes. Many filters do not adequately sanitize attributes against the presence of potentially dangerous commands even if they adequately sanitize tags. For example, dangerous expressions could be inserted into a style attribute in an anchor tag, resulting in the execution of malicious code when the resulting page is rendered. If a victim is tricked into viewing the rendered page the attack proceeds like a normal XSS attack, possibly resulting in the loss of sensitive cookies or other malicious activities.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-243 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser, PWN::Plugins::Zaproxy; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-243 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-243`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for user-controllable inputs] Using a browser or an automated tool, an adversary follows all public links and actions on a web site. They record all the links, the forms, the resources accessed and all other potential entry-points for the web application. | techniques: Use a spidering tool to follow and record all links and analyze the web pages to find e…
- Step 2 (Experiment): [Probe identified potential entry points for XSS targeting HTML attributes] The adversary uses the entry points gathered in the "Explore" phase as a target list and injects various malicious expressions as input, hoping to embed them as HTML attributes. | techniques: Inject single and double quotes into URL parameters or other inputs to see if they are filtered out. Also use…
- Step 3 (Experiment): [Craft malicious XSS URL] Once the adversary has determined which parameters are vulnerable to XSS, they will craft a malicious URL containing the XSS exploit. The adversary can have many goals, from stealing session IDs, cookies, credentials, and page content from the victim. | techniques: Execute a script using an expression embedded in an HTML attribute, which avoids needi…
- Step 4 (Exploit): [Get victim to click URL] In order for the attack to be successful, the victim needs to access the malicious URL. | techniques: Send a phishing email to the victim containing the malicious URL. This can be hidden in a hyperlink as to not show the full URL, which might draw suspicion.; Put the malicious URL on a public forum, where many victims might accidentally click the link.

## Prerequisites

- The target application must fail to adequately sanitize HTML attributes against the presence of dangerous commands.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- The adversary must trick the victim into following a crafted link to a vulnerable server or view a web post where the dangerous commands are executed.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Design: Use libraries and templates that minimize unfiltered input.
- Implementation: Normalize, filter and use an allowlist for all input including that which is not expected to have any scripting content.
- Implementation: The victim should configure the browser to minimize active content from untrusted sources.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-591](CAPEC-591.md)
- ChildOf → [CAPEC-592](CAPEC-592.md)
- ChildOf → [CAPEC-588](CAPEC-588.md)

## Related CWEs (run the cwe skill)

- [CWE-83](../cwe/references/CWE-83.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-243 and CWE IDs
