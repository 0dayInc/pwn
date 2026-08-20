# CAPEC-182: Flash Injection

- Catalog: [CAPEC-182](https://capec.mitre.org/data/definitions/182.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An attacker tricks a victim to execute malicious flash content that executes commands or makes flash calls specified by the attacker. One example of this attack is cross-site flashing, an attacker controlled parameter to a reference call loads from content specified by the attacker.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-182 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-182 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-182`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find Injection Entry Points] The attacker first takes an inventory of the entry points of the application. | techniques: Spider the website for all available URLs that reference a Flash application.; List all uninitialized global variables (such as _root.*, _global.*, _level0.*) in ActionScript, registered global variables in included files, load variables to external movies.
- Step 2 (Experiment): [Determine the application's susceptibility to Flash injection] Determine the application's susceptibility to Flash injection. For each URL identified in the explore phase, the attacker attempts to use various techniques such as direct load asfunction, controlled evil page/host, Flash HTML injection, and DOM injection to determine whether the application is susceptible to Fla…
- Step 3 (Exploit): [Inject malicious content into target] Inject malicious content into target utilizing vulnerable injection vectors identified in the Experiment phase

## Prerequisites

- The target must be capable of running Flash applications. In some cases, the victim must follow an attacker-supplied link.

## Skills required

- Medium: The attacker needs to have knowledge of Flash, especially how to insert content the executes commands.

## Resources required

- None: No specialized resources are required to execute this type of attack. The attacker may need to be able to serve the injected Flash content.

## Oracles (consequences)

- Confidentiality: Other — Information Leakage
- Integrity: Modify Data
- Confidentiality: Read Data
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Implementation: remove sensitive information such as user name and password in the SWF file.
- Implementation: use validation on both client and server side.
- Implementation: remove debug information.
- Implementation: use SSL when loading external data
- Implementation: use crossdomain.xml file to allow the application domain to load stuff or the SWF file called by other domain.

## Example instances (payload / topology hints)

- In the following example, the SWF file contains getURL('javascript:SomeFunc("someValue")','','GET') A request like http://example.com/noundef.swf?a=0:0;alert('XSS') becomes javascript:SomeFunc("someValue")?a=0:0;alert(123)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-137](CAPEC-137.md)
- CanAlsoBe → [CAPEC-248](CAPEC-248.md)

## Related CWEs (run the cwe skill)

- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-184](../cwe/references/CWE-184.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-182 and CWE IDs
