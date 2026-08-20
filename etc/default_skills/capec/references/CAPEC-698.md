# CAPEC-698: Install Malicious Extension

- Catalog: [CAPEC-698](https://capec.mitre.org/data/definitions/698.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary directly installs or tricks a user into installing a malicious extension into existing trusted software, with the goal of achieving a variety of negative technical impacts.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-698 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-698 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-698`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target(s)] The adversary must first identify target software that allows for extensions/plugins and which they wish to exploit, such as a web browser or desktop application. To increase the attack space, this will often be popular software with a large user-base.
- Step 2 (Experiment): [Create malicious extension] Having identified a suitable target, the adversary crafts a malicious extension/plugin that can be installed by the underlying target software. This malware may be targeted to execute on specific operating systems or be operating system agnostic.
- Step 3 (Exploit): [Install malicious extension] The malicious extension/plugin is installed by the underlying target software and executes the adversary-created malware, resulting in a variety of negative technical impacts. | techniques: Adversary-Installed: Having already compromised the target system, the adversary simply installs the malicious extension/plugin themself.; User-Installed: The ad…

## Prerequisites

- The adversary must craft malware based on the type of software and system(s) they intend to exploit.
- If the adversary intends to install the malicious extension themself, they must first compromise the target machine via some other means.

## Skills required

- Medium: Ability to create malicious extensions that can exploit specific software applications and systems.
- Medium: Optional: Ability to exploit target system(s) via other means in order to gain entry.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Access Control: Read Data
- Integrity, Access Control: Modify Data
- Authorization, Access Control: Execute Unauthorized Commands, Alter Execution Logic, Gain Privileges

## Mitigations to bypass

- Only install extensions/plugins from official/verifiable sources.
- Confirm extensions/plugins are legitimate and not malware masquerading as a legitimate extension/plugin.
- Ensure the underlying software leveraging the extension/plugin (including operating systems) is up-to-date.
- Implement an extension/plugin allow list, based on the given security policy.
- If applicable, confirm extensions/plugins are properly signed by the official developers.
- For web browsers, close sessions when finished to prevent malicious extensions/plugins from executing the the background.

## Example instances (payload / topology hints)

- In January 2018, Palo Alto's Unit 42 reported that a malicious Internet Information Services (IIS) extension they named RGDoor was used to create a backdoor into several Middle Eastern government organizations, as well as a financial institution and an educational institution. This malware was used in conjunction with the TwoFace webshell and allowed the adversaries to upload/download files and e…
- In December 2018, it was reported that North Korea-based APT Kimusky (also known as Velvet Chollima) infected numerous legitimate academic organizations within the U.S., many specializing in biomedical engineering, with a malicious Google Chrome extension. Dubbed "Operation STOLEN PENCIL", the attack entailed conducting spear-phishing attacks to trick victims into installing a malicious PDF reade…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-542](CAPEC-542.md)

## Related CWEs (run the cwe skill)

- [CWE-507](../cwe/references/CWE-507.md) — run that CWE procedure after this CAPEC flow
- [CWE-829](../cwe/references/CWE-829.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-698 and CWE IDs
