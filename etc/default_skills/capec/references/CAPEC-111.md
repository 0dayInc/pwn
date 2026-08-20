# CAPEC-111: JSON Hijacking (aka JavaScript Hijacking)

- Catalog: [CAPEC-111](https://capec.mitre.org/data/definitions/111.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker targets a system that uses JavaScript Object Notation (JSON) as a transport mechanism between the client and the server (common in Web 2.0 systems using AJAX) to steal possibly confidential information transmitted from the server back to the client inside the JSON object by taking advantage of the loophole in the browser's Same Origin Policy that does not prohibit JavaScript from one website to be included and executed in the context of another website.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-111 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-111 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-111`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Understand How to Request JSON Responses from the Target System] An attacker first explores the target system to understand what URLs need to be provided to it in order to retrieve JSON objects that contain information of interest to the attacker. | techniques: An attacker creates an account with the target system and observes requests and the corresponding JSON responses from…
- Step 2 (Experiment): [Craft a malicious website] The attacker crafts a malicious website to which they plan to lure the victim who is using the vulnerable target system. The malicious website does two things: 1. Contains a hook that intercepts incoming JSON objects, reads their contents and forwards the contents to the server controlled by the attacker (via a new XMLHttpRequest). 2. Uses the scri…
- Step 3 (Exploit): [Launch JSON hijack] An attacker lures the victim to the malicious website or leverages other means to get their malicious code executing in the victim's browser. Once that happens, the malicious code makes a request to the victim target system to retrieve a JSON object with sensitive information. The request includes the victim's session cookie if the victim is logged in. | tec…

## Prerequisites

- JSON is used as a transport mechanism between the client and the server
- The target server cannot differentiate real requests from forged requests
- The JSON object returned from the server can be accessed by the attackers' malicious code via a script tag

## Skills required

- Medium: Once this attack pattern is developed and understood, creating an exploit is not very complex.The attacker needs to have knowledge of the URLs that need to be accessed on the target system to request the JSON objects.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- Ensure that server side code can differentiate between legitimate requests and forged requests. The solution is similar to protection against Cross Site Request Forger (CSRF), which is to use a hard to guess random nonce (that is unique to the victim's session with the server) that the attacker has no way of knowing (at least in the absence of other weaknesses). Each request from the client to th…
- On the client side, the system's design could make it difficult to get access to the JSON object content via the script tag. Since the JSON object is never assigned locally to a variable, it cannot be readily modified by the attacker before being used by a script tag. For instance, if while(1) was added to the beginning of the JavaScript returned by the server, trying to access it with a script t…
- Make the URLs in the system used to retrieve JSON objects unpredictable and unique for each user session.
- Ensure that to the extent possible, no sensitive data is passed from the server to the client via JSON objects. JavaScript was never intended to play that role, hence the same origin policy does not adequate address this scenario.

## Example instances (payload / topology hints)

- Gmail service was found to be vulnerable to a JSON Hijacking attack that enabled an attacker to get the contents of the victim's address book. An attacker could send an e-mail to the victim's Gmail account (which ensures that the victim is logged in to Gmail when they receive it) with a link to the attackers' malicious site. If the victim clicked on the link, a request (containing the victim's au…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-212](CAPEC-212.md)

## Related CWEs (run the cwe skill)

- [CWE-345](../cwe/references/CWE-345.md) — run that CWE procedure after this CAPEC flow
- [CWE-346](../cwe/references/CWE-346.md) — run that CWE procedure after this CAPEC flow
- [CWE-352](../cwe/references/CWE-352.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-111 and CWE IDs
