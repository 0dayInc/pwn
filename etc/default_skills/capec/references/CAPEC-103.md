# CAPEC-103: Clickjacking

- Catalog: [CAPEC-103](https://capec.mitre.org/data/definitions/103.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary tricks a victim into unknowingly initiating some action in one system while interacting with the UI from a seemingly completely different, usually an adversary controlled or intended, system.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-103 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-103 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-103`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Experiment): [Craft a clickjacking page] The adversary utilizes web page layering techniques to try to craft a malicious clickjacking page | techniques: The adversary leveraged iframe overlay capabilities to craft a malicious clickjacking page; The adversary leveraged Flash file overlay capabilities to craft a malicious clickjacking page; The adversary leveraged Silverlight overlay capabi…
- Step 2 (Exploit): [Adversary lures victim to clickjacking page] Adversary utilizes some form of temptation, misdirection or coercion to lure the victim to loading and interacting with the clickjacking page in a way that increases the chances that the victim will click in the right areas. | techniques: Lure the victim to the malicious site by sending the victim an e-mail with a URL to the site.; L…
- Step 3 (Exploit): [Trick victim into interacting with the clickjacking page in the desired manner] The adversary tricks the victim into clicking on the areas of the UI which contain the hidden action controls and thereby interacts with the target system maliciously with the victim's level of privilege. | techniques: Hide action controls over very commonly used functionality.; Hide action controls…

## Prerequisites

- The victim is communicating with the target application via a web based UI and not a thick client
- The victim's browser security policies allow at least one of the following JavaScript, Flash, iFrames, ActiveX, or CSS.
- The victim uses a modern browser that supports UI elements like clickable buttons (i.e. not using an old text only browser)
- The victim has an active session with the target system.
- The target system's interaction window is open in the victim's browser and supports the ability for initiating sensitive actions on behalf of the user in the target system

## Skills required

- High: Crafting the proper malicious site and luring the victim to this site are not trivial tasks.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Integrity: Modify Data
- Confidentiality: Read Data
- Availability: Unreliable Execution

## Mitigations to bypass

- If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.
- Turn off JavaScript, Flash and disable CSS.
- When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.

## Example instances (payload / topology hints)

- A victim has an authenticated session with a site that provides an electronic payment service to transfer funds between subscribing members. At the same time, the victim receives an e-mail that appears to come from an online publication to which they subscribe with links to today's news articles. The victim clicks on one of these links and is taken to a page with the news story. There is a screen…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-173](CAPEC-173.md)

## Related CWEs (run the cwe skill)

- [CWE-1021](../cwe/references/CWE-1021.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-103 and CWE IDs
