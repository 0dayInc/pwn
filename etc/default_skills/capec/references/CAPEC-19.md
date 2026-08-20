# CAPEC-19: Embedding Scripts within Scripts

- Catalog: [CAPEC-19](https://capec.mitre.org/data/definitions/19.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary leverages the capability to execute their own script by embedding it within other scripts that the target software is likely to execute due to programs' vulnerabilities that are brought on by allowing remote hosts to execute scripts.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-19 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-19 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-19`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Spider] Using a browser or an automated tool, an adversary records all entry points for inputs that happen to be reflected in a client-side script element. These script elements can be located in the HTML content (head, body, comments), in an HTML tag, XML, CSS, etc. | techniques: Use a spidering tool to follow and record all non-static links that are likely to have input param…
- Step 2 (Experiment): [Probe identified potential entry points for XSS vulnerability] The adversary uses the entry points gathered in the "Explore" phase as a target list and injects various common script payloads to determine if an entry point actually represents a vulnerability and to characterize the extent to which the vulnerability can be exploited. | techniques: Manually inject various scrip…
- Step 3 (Exploit): [Steal session IDs, credentials, page content, etc.] As the adversary succeeds in exploiting the vulnerability, they can choose to steal user's credentials in order to reuse or to analyze them later on. | techniques: Develop malicious JavaScript that is injected through vectors identified during the Experiment Phase and loaded by the victim's browser and sends document informati…
- Step 4 (Exploit): [Forceful browsing] When the adversary targets the current application or another one (through CSRF vulnerabilities), the user will then be the one who perform the attacks without being aware of it. These attacks are mostly targeting application logic flaws, but it can also be used to create a widespread attack against a particular website on the user's current network (Internet…
- Step 5 (Exploit): [Content spoofing] By manipulating the content, the adversary targets the information that the user would like to get from the website. | techniques: Develop malicious JavaScript that is injected through vectors identified during the Experiment Phase and loaded by the victim's browser and exposes adversary-modified invalid information to the user on the current web p…

## Prerequisites

- Target software must be able to execute scripts, and also grant the adversary privilege to write/upload scripts.

## Skills required

- Low: To load malicious script into open, e.g. world writable directory
- Medium: Executing remote scripts on host and collecting output

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Use browser technologies that do not allow client side scripting.
- Utilize strict type, character, and encoding enforcement.
- Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.
- Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Perform input validation for all remote content.
- Perform output validation for all remote content.
- Disable scripting languages such as JavaScript in browser
- Session tokens for specific host
- Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.
- Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

## Example instances (payload / topology hints)

- Ajax applications enable rich functionality for browser based web applications. Applications like Google Maps deliver unprecedented ability to zoom in and out, scroll graphics, and change graphic presentation through Ajax. The security issues that an adversary may exploit in this instance are the relative lack of security features in JavaScript and the various browser's implementation of JavaScri…
- ~/.bash_profile and ~/.bashrc are executed in a user's context when a new shell opens or when a user logs in so that their environment is set correctly. ~/.bash_profile is executed for login shells and ~/.bashrc is executed for interactive non-login shells. This means that when a user logs in (via username and password) to the console (either locally or remotely via something like SSH), ~/.bash_p…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-242](CAPEC-242.md)

## Related CWEs (run the cwe skill)

- [CWE-284](../cwe/references/CWE-284.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-19 and CWE IDs
