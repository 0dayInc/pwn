# CAPEC-6: Argument Injection

- Catalog: [CAPEC-6](https://capec.mitre.org/data/definitions/6.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker changes the behavior or state of a targeted application through injecting data or command syntax through the targets use of non-validated and non-filtered arguments of exposed services or methods.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-6 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-6 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-6`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Discovery of potential injection vectors] Using an automated tool or manual discovery, the attacker identifies services or methods with arguments that could potentially be used as injection vectors (OS, API, SQL procedures, etc.). | techniques: Manually cover the application and record the possible places where arguments could be passed into external systems.; Use a spider, for…
- Step 2 (Experiment): [1. Attempt variations on argument content] Possibly using an automated tool, the attacker will perform injection variations of the arguments. | techniques: Use a very large list of probe strings in order to detect if there is a positive result, and, what type of system has been targeted (if obscure).; Use a proxy tool to record results, error messages and/or log if accessibl…
- Step 3 (Exploit): [Abuse of the application] The attacker injects specific syntax into a particular argument in order to generate a specific malicious effect in the targeted application. | techniques: Manually inject specific payload into targeted argument.

## Prerequisites

- Target software fails to strip all user-supplied input of any content that could cause the shell to perform unexpected actions.
- Software must allow for unvalidated or unfiltered input to be executed on operating system shell, and, optionally, the system configuration must allow for output to be sent back to client.

## Skills required

- Medium: The attacker has to identify injection vector, identify the operating system-specific commands, and optionally collect the output.

## Resources required

- Ability to communicate synchronously or asynchronously with server. Optionally, ability to capture output directly through synchronous communication or other method such as FTP.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Integrity: Modify Data
- Confidentiality: Read Data

## Mitigations to bypass

- Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.
- Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.
- Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.

## Example instances (payload / topology hints)

- A recent example instance of argument injection occurred against Java Web Start technology, which eases the client side deployment for Java programs. The JNLP files that are used to describe the properties for the program. The client side Java runtime used the arguments in the property setting to define execution parameters, but if the attacker appends commands to an otherwise legitimate property…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-137](CAPEC-137.md)

## Related CWEs (run the cwe skill)

- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-146](../cwe/references/CWE-146.md) — run that CWE procedure after this CAPEC flow
- [CWE-184](../cwe/references/CWE-184.md) — run that CWE procedure after this CAPEC flow
- [CWE-78](../cwe/references/CWE-78.md) — run that CWE procedure after this CAPEC flow
- [CWE-185](../cwe/references/CWE-185.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-6 and CWE IDs
