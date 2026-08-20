# CAPEC-62: Cross Site Request Forgery

- Catalog: [CAPEC-62](https://capec.mitre.org/data/definitions/62.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An attacker crafts malicious web links and distributes them (via web pages, email, etc.), typically in a targeted manner, hoping to induce users to click on the link and execute the malicious action against some third-party application. If successful, the action embedded in the malicious link will be processed and accepted by the targeted application with the users' privilege level. This type of attack leverages the persistence and implicit trust placed in user session cookies by many web applications today. In such an architecture, once the user authenticates to an application and a session cookie is created on the user's system, all following transactions for that session are authenticated using that cookie including potential actions initiated by an attacker and simply "riding" the existing session cookie.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-62 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-62 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-62`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Explore target website] The attacker first explores the target website to determine pieces of functionality that are of interest to them (e.g. money transfers). The attacker will need a legitimate user account on the target website. It would help to have two accounts. | techniques: Use web application debugging tool such as WebScarab, Tamper Data or TamperIE to analyze the info…
- Step 2 (Experiment): [Create a link that when clicked on, will execute the interesting functionality.] The attacker needs to create a link that will execute some interesting functionality such as transfer money, change a password, etc. | techniques: Create a GET request containing all required parameters (e.g. https://www.somebank.com/members/transfer.asp?to=012345678901&amt=10000); Create a form…
- Step 3 (Exploit): [Convince user to click on link] Finally, the attacker needs to convince a user that is logged into the target website to click on a link to execute the CSRF attack. | techniques: Execute a phishing attack and send the user an e-mail convincing them to click on a link.; Execute a stored XSS attack on a website to permanently embed the malicious link into the website.; Execute a…

## Prerequisites

- (none listed in CAPEC catalog)

## Skills required

- Medium: The attacker needs to figure out the exact invocation of the targeted malicious action and then craft a link that performs the said action. Having the user click on such a link is often accomplished by sending an email or posting such a link to a bulletin board or the likes.

## Resources required

- All the attacker needs is the exact representation of requests to be made to the application and to be able to get the malicious link across to a victim.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.
- Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.
- Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before p…
- In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

## Example instances (payload / topology hints)

- While a user is logged into their bank account, an attacker can send an email with some potentially interesting content and require the user to click on a link in the email. The link points to or contains an attacker setup script, probably even within an iFrame, that mimics an actual user form submission to perform a malicious activity, such as transferring funds from the victim's account. The at…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-21](CAPEC-21.md)

## Related CWEs (run the cwe skill)

- [CWE-352](../cwe/references/CWE-352.md) — run that CWE procedure after this CAPEC flow
- [CWE-306](../cwe/references/CWE-306.md) — run that CWE procedure after this CAPEC flow
- [CWE-664](../cwe/references/CWE-664.md) — run that CWE procedure after this CAPEC flow
- [CWE-732](../cwe/references/CWE-732.md) — run that CWE procedure after this CAPEC flow
- [CWE-1275](../cwe/references/CWE-1275.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-62 and CWE IDs
