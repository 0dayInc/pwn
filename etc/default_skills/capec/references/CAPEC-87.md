# CAPEC-87: Forceful Browsing

- Catalog: [CAPEC-87](https://capec.mitre.org/data/definitions/87.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker employs forceful browsing (direct URL entry) to access portions of a website that are otherwise unreachable. Usually, a front controller or similar design pattern is employed to protect access to portions of a web application. Forceful browsing enables an attacker to access information, perform privileged operations and otherwise reach sections of the web application that have been improperly protected.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-87 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-87 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-87`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Spider] Using an automated tool, an attacker follows all public links on a web site. They record all the links they find. | techniques: Use a spidering tool to follow and record all links.; Use a proxy tool to record all links visited during a manual traversal of the web application.
- Step 2 (Experiment): [Attempt well-known or guessable resource locations] Using an automated tool, an attacker requests a variety of well-known URLs that correspond to administrative, debugging, or other useful internal actions. They record all the positive responses from the server. | techniques: Use a spidering tool to follow and record attempts on well-known URLs.; Use a proxy tool to record a…
- Step 3 (Exploit): [Use unauthorized resources] By visiting the unprotected resource, the attacker makes use of unauthorized functionality. | techniques: Access unprotected functions and execute them.
- Step 4 (Exploit): [View unauthorized data] The attacker discovers and views unprotected sensitive data. | techniques: Direct request of protected pages that directly access database back-ends. (e.g., list.jsp, accounts.jsp, status.jsp, etc.)

## Prerequisites

- The forcibly browseable pages or accessible resources must be discoverable and improperly protected.

## Skills required

- Low: Forcibly browseable pages can be discovered by using a number of automated tools. Doing the same manually is tedious but by no means difficult.

## Resources required

- None: No specialized resources are required to execute this type of attack. A directory listing is helpful, but not a requirement.

## Oracles (consequences)

- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Authenticate request to every resource. In addition, every page or resource must ensure that the request it is handling has been made in an authorized context.
- Forceful browsing can also be made difficult to a large extent by not hard-coding names of application pages or resources. This way, the attacker cannot figure out, from the application alone, the resources available from the present context.

## Example instances (payload / topology hints)

- A bulletin board application provides an administrative interface at admin.aspx when the user logging in belongs to the administrators group. An attacker can access the admin.aspx interface by making a direct request to the page. Not having access to the interface appropriately protected allows the attacker to perform administrative functions without having to authenticate themself in that role.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-115](CAPEC-115.md)

## Related CWEs (run the cwe skill)

- [CWE-425](../cwe/references/CWE-425.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-87 and CWE IDs
