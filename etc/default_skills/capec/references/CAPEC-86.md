# CAPEC-86: XSS Through HTTP Headers

- Catalog: [CAPEC-86](https://capec.mitre.org/data/definitions/86.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits web applications that generate web content, such as links in a HTML page, based on unvalidated or improperly validated data submitted by other actors. XSS in HTTP Headers attacks target the HTTP headers which are hidden from most users and may not be validated by web applications.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-86 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser, PWN::Plugins::Zaproxy

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-86 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-86`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for public links] Using a browser or an automated tool, an adversary follows all public links on a web site. They record all the entry points (input) that becomes part of generated HTTP header (not only GET/POST/COOKIE, but also Content-Type, etc.) | techniques: Use a spidering tool to follow and record all links and analyze the web pages to find entry po…
- Step 2 (Experiment): [Probe identified potential entry points for XSS vulnerability] The adversary uses the entry points gathered in the "Explore" phase as a target list and injects various common script payloads to determine if an entry point actually represents a vulnerability and to characterize the extent to which the vulnerability can be exploited. They record all the responses from the serv…
- Step 3 (Experiment): [Craft malicious XSS URL] Once the adversary has determined which parameters are vulnerable to XSS, they will craft a malicious URL containing the XSS exploit. The adversary can have many goals, from stealing session IDs, cookies, credentials, and page content from the victim. | techniques: Change a URL parameter which is used in an HTTP header to include a malicious script t…
- Step 4 (Exploit): [Get victim to click URL] In order for the attack to be successful, the victim needs to access the malicious URL. | techniques: Send a phishing email to the victim containing the malicious URL. This can be hidden in a hyperlink as to not show the full URL, which might draw suspicion.; Put the malicious URL on a public forum, where many victims might accidentally click the link.

## Prerequisites

- Target software must be a client that allows scripting communication from remote hosts.

## Skills required

- Low: To achieve a redirection and use of less trusted source, an adversary can simply edit HTTP Headers that are sent to client machine.
- High: Exploiting a client side vulnerability to inject malicious scripts into the browser's executable process.

## Resources required

- The adversary must have the ability to deploy a custom hostile service for access by targeted clients and the abbility to communicate synchronously or asynchronously with client machine. The adversary must also control a remote site of some sort to redirect client and data to.

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Design: Use browser technologies that do not allow client side scripting.
- Design: Utilize strict type, character, and encoding enforcement
- Design: Server side developers should not proxy content via XHR or other means, if a http proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Perform input validation for all remote content.
- Implementation: Perform output validation for all remote content.
- Implementation: Disable scripting languages such as JavaScript in browser
- Implementation: Session tokens for specific host
- Implementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

## Example instances (payload / topology hints)

- Utilize a remote style sheet set in the HTTP header for XSS attack. When the adversary is able to point to a remote stylesheet, any of the variables set in that stylesheet are controllable on the client side by the remote adversary. Like most XSS attacks, results vary depending on browser that is used [REF-97]. <META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">
- Google's 404 redirection script was found vulnerable to this attack vector. Google's 404 file not found page read * Response headers: "Content-Type: text/html; charset=[encoding]". * Response body: <META http-equiv="Content-Type" (...) charset=[encoding]/> If the response sends an unexpected encoding type such as UTF-7, then no enforcement is done on the payload and arbitrary XSS code will be tra…
- XSS can be used in variety of ways, because it is scripted and executes in a distributed, asynchronous fashion it can create its own vector and openings. For example, the adversary can use XSS to mount a DDoS attack by having series of different computers unknowingly executing requests against a single host.

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
- [ ] Finding (if any) cites CAPEC-86 and CWE IDs
