# CAPEC-104: Cross Zone Scripting

- Catalog: [CAPEC-104](https://capec.mitre.org/data/definitions/104.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker is able to cause a victim to load content into their web-browser that bypasses security zone controls and gain access to increased privileges to execute scripting code or other web objects such as unsigned ActiveX controls or applets. This is a privilege elevation attack targeted at zone-based web-browser security.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-104 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-104 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-104`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find systems susceptible to the attack] Find systems that contain functionality that is accessed from both the internet zone and the local zone. There needs to be a way to supply input to that functionality from the internet zone and that original input needs to be used later on a page from a local zone. | techniques: Leverage knowledge of common local zone functionality on tar…
- Step 2 (Experiment): [Find the insertion point for the payload] The attacker first needs to find some system functionality or possibly another weakness in the system (e.g. susceptibility to cross site scripting) that would provide the attacker with a mechanism to deliver the payload (i.e. the code to be executed) to the user. The location from which this code is executed in the user's browser nee…
- Step 3 (Exploit): [Craft and inject the payload] Develop the payload to be executed in the higher privileged zone in the user's browser. Inject the payload and attempt to lure the victim (if possible) into executing the functionality which unleashes the payload. | techniques: The attacker makes it as likely as possible that the vulnerable functionality into which they have injected the payload ha…

## Prerequisites

- The target must be using a zone-aware browser.

## Skills required

- Medium: Ability to craft malicious scripts or find them elsewhere and ability to identify functionality that is running web controls in the local zone and to find an injection vector into that functionality

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Disable script execution.
- Ensure that sufficient input validation is performed for any potentially untrusted data before it is used in any privileged context or zone
- Limit the flow of untrusted data into the privileged areas of the system that run in the higher trust zone
- Limit the sites that are being added to the local machine zone and restrict the privileges of the code running in that zone to the bare minimum
- Ensure proper HTML output encoding before writing user supplied data to the page

## Example instances (payload / topology hints)

- There was a cross zone scripting vulnerability discovered in Skype that allowed one user to upload a video with a maliciously crafted title that contains a script. Subsequently, when the victim attempts to use the "add video to chat" feature on attacker's video, the script embedded in the title of the video runs with local zone privileges. Skype is using IE web controls to render internal and ext…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-233](CAPEC-233.md)

## Related CWEs (run the cwe skill)

- [CWE-250](../cwe/references/CWE-250.md) — run that CWE procedure after this CAPEC flow
- [CWE-638](../cwe/references/CWE-638.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-116](../cwe/references/CWE-116.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-104 and CWE IDs
