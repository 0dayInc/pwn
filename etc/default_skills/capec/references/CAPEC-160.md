# CAPEC-160: Exploit Script-Based APIs

- Catalog: [CAPEC-160](https://capec.mitre.org/data/definitions/160.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

Some APIs support scripting instructions as arguments. Methods that take scripted instructions (or references to scripted instructions) can be very flexible and powerful. However, if an attacker can specify the script that serves as input to these methods they can gain access to a great deal of functionality. For example, HTML pages support <script> tags that allow scripting languages to be embedded in the page and then interpreted by the receiving web browser. If the content provider is malicious, these scripts can compromise the client application. Some applications may even execute the scripts under their own identity (rather than the identity of the user providing the script) which can allow attackers to perform activities that would otherwise be denied to them.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-160 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-160 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-160`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify API] Discover an API of interest by exploring application documentation or observing responses to API calls | techniques: Search via internet for known, published APIs that support scripting instructions as arguments
- Step 2 (Experiment): [Test simple script] Adversaries will attempt to give a smaller script as input to the API, such as simply printing to the console, to see if the attack is viable. | techniques: Create a general script to be taken as input by the API
- Step 3 (Exploit): [Give malicious scripting instructions to API] Adversaries will now craft custom scripts to do malicious behavior. Depending on the setup of the application this script could be run with user or admin level priveleges. | techniques: Crafting a malicious script to be run on a system based on priveleges and capabilities of the system

## Prerequisites

- The target application must include the use of APIs that execute scripts.
- The target application must allow the attacker to provide some or all of the arguments to one of these script interpretation methods and must fail to adequately filter these arguments for dangerous or unwanted script commands.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-113](CAPEC-113.md)

## Related CWEs (run the cwe skill)

- [CWE-346](../cwe/references/CWE-346.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-160 and CWE IDs
