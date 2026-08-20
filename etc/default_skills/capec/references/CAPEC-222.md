# CAPEC-222: iFrame Overlay

- Catalog: [CAPEC-222](https://capec.mitre.org/data/definitions/222.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

In an iFrame overlay attack the victim is tricked into unknowingly initiating some action in one system while interacting with the UI from seemingly completely different system.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-222 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-222 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-222`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Craft an iFrame Overlay page] The adversary crafts a malicious iFrame overlay page. | techniques: The adversary leverages iFrame overlay capabilities to craft a malicious iFrame overlay page.
- Step 2 (Exploit): [adversary tricks victim to load the iFrame overlay page] adversary utilizes some form of temptation, misdirection or coercion to trick the victim to loading and interacting with the iFrame overlay page in a way that increases the chances that the victim will visit the malicious page. | techniques: Trick the victim to the malicious site by sending the victim an e-mail with a URL…
- Step 3 (Exploit): [Trick victim into interacting with the iFrame overlay page in the desired manner] The adversary tricks the victim into clicking on the areas of the UI which contain the hidden action controls and thereby interacts with the target system maliciously with the victim's level of privilege. | techniques: Hide action controls over very commonly used functionality.; Hide action contro…

## Prerequisites

- The victim is communicating with the target application via a web based UI and not a thick client. The victim's browser security policies allow iFrames. The victim uses a modern browser that supports UI elements like clickable buttons (i.e. not using an old text only browser). The victim has an active session with the target system. The target system's interaction window is open in the victim's b…

## Skills required

- High: Crafting the proper malicious site and luring the victim to this site is not a trivial task.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Configuration: Disable iFrames in the Web browser.
- Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.
- Operation: If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.

## Example instances (payload / topology hints)

- The following example is a real-world iFrame overlay attack [2]. In this attack, the malicious page embeds Twitter.com on a transparent IFRAME. The status-message field is initialized with the URL of the malicious page itself. To provoke the click, which is necessary to publish the entry, the malicious page displays a button labeled "Don't Click." This button is aligned with the invisible "Update…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-103](CAPEC-103.md)

## Related CWEs (run the cwe skill)

- [CWE-1021](../cwe/references/CWE-1021.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-222 and CWE IDs
