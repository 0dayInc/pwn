# CAPEC-107: Cross Site Tracing

- Catalog: [CAPEC-107](https://capec.mitre.org/data/definitions/107.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

Cross Site Tracing (XST) enables an adversary to steal the victim's session cookie and possibly other authentication credentials transmitted in the header of the HTTP request when the victim's browser communicates to a destination system's web server.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-107 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-107 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-107`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine if HTTP Trace is enabled] Determine if HTTP Trace is enabled at the web server with which the victim has an active session | techniques: An adversary may issue an HTTP Trace request to the target web server and observe if the response arrives with the original request in the body of the response.
- Step 2 (Experiment): [Identify mechanism to launch HTTP Trace request] The adversary attempts to force the victim to issue an HTTP Trace request to the targeted application. | techniques: The adversary probes for cross-site scripting vulnerabilities to force the victim into issuing an HTTP Trace request.
- Step 3 (Exploit): [Create a malicious script that pings the web server with HTTP TRACE request] The adversary creates a malicious script that will induce the victim's browser to issue an HTTP TRACE request to the destination system's web server. The script will further intercept the response from the web server, pick up sensitive information out of it, and forward to the site controlled by the ad…
- Step 4 (Exploit): [Execute malicious HTTP Trace launching script] The adversary leverages an XSS vulnerability to force the victim to execute the malicious HTTP Trace launching script
- Step 5 (Exploit): [Intercept HTTP TRACE response] The adversary's script intercepts the HTTP TRACE response from teh web server, glance sensitive information from it, and forward that information to a server controlled by the adversary.

## Prerequisites

- HTTP TRACE is enabled on the web server
- The destination system is susceptible to XSS or an adversary can leverage some other weakness to bypass the same origin policy
- Scripting is enabled in the client's browser
- HTTP is used as the communication protocol between the server and the client

## Skills required

- Medium: Understanding of the HTTP protocol and an ability to craft a malicious script

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Integrity: Modify Data

## Mitigations to bypass

- Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default.
- Patch web browser against known security origin policy bypass exploits.

## Example instances (payload / topology hints)

- An adversary determines that a particular system is vulnerable to reflected cross-site scripting (XSS) and endeavors to leverage this weakness to steal the victim's authentication cookie. An adversary realizes that since httpOnly attribute is set on the user's cookie, it is not possible to steal it directly with their malicious script. Instead, the adversary has their script use XMLHTTP ActiveX c…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-593](CAPEC-593.md)

## Related CWEs (run the cwe skill)

- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow
- [CWE-648](../cwe/references/CWE-648.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-107 and CWE IDs
