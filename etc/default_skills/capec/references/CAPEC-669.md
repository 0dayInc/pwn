# CAPEC-669: Alteration of a Software Update

- Catalog: [CAPEC-669](https://capec.mitre.org/data/definitions/669.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary with access to an organization’s software update infrastructure inserts malware into the content of an outgoing update to fielded systems where a wide range of malicious effects are possible. With the same level of access, the adversary can alter a software update to perform specific malicious acts including granting the adversary control over the software’s normal functionality.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-669 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-669 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-669`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify software with frequent updates] The adversary must first identify a target software that has updates at least with some frequency, enough that there is am update infrastructure.
- Step 2 (Experiment): [Gain access to udpate infrastructure] The adversary must then gain access to the organization's software update infrastructure. This can either be done by gaining remote access from outside the organization, or by having a malicious actor inside the organization gain access. It is often easier if someone within the organization gains access.
- Step 3 (Exploit): [Alter the software update] Through access to the software update infrastructure, an adversary will alter the software update by injecting malware into the content of an outgoing update.

## Prerequisites

- An adversary would need to have penetrated an organization’s software update infrastructure including gaining access to components supporting the configuration management of software versions and updates related to the software maintenance of customer systems.

## Skills required

- High: Skills required include the ability to infiltrate the organization’s software update infrastructure either from the Internet or from within the organization, including subcontractors, and be able to change software being delivered to customer/user systems in an undetected manner.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Access Control: Gain Privileges
- Authorization: Execute Unauthorized Commands
- Integrity: Modify Data
- Confidentiality: Read Data

## Mitigations to bypass

- Have a Software Assurance Plan that includes maintaining strict configuration management control of source code, object code and software development, build and distribution tools; manual code reviews and static code analysis for developmental software; and tracking of all storage and movement of code.
- Require elevated privileges for distribution of software and software updates.

## Example instances (payload / topology hints)

- A subcontractor to a software developer injects maliciously altered software updates into an automated update process that distributes to government and commercial customers software containing a hidden backdoor.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-184](CAPEC-184.md)
- CanPrecede → [CAPEC-673](CAPEC-673.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-669 and CWE IDs
