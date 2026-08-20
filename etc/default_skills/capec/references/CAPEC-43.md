# CAPEC-43: Exploiting Multiple Input Interpretation Layers

- Catalog: [CAPEC-43](https://capec.mitre.org/data/definitions/43.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker supplies the target software with input data that contains sequences of special characters designed to bypass input validation logic. This exploit relies on the target making multiples passes over the input data and processing a "layer" of special characters with each pass. In this manner, the attacker can disguise input that would otherwise be rejected as invalid by concealing it with layers of special/escape characters that are stripped off by subsequent processing steps. The goal is to first discover cases where the input validation layer executes before one or more parsing layers. That is, user input may go through the following logic in an application: <parser1> --> <input validator> --> <parser2>. In such cases, the attacker will need to provide input that will pass through the input validator, but after passing through parser2, will be converted into something that the input validator was supposed to stop.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-43 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-43 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-43`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine application/system inputs where bypassing input validation is desired] The attacker first needs to determine all of the application's/system's inputs where input validation is being performed and where they want to bypass it. | techniques: While using an application/system, the attacker discovers an input where validation is stopping them from performing some maliciou…
- Step 2 (Experiment): [Determine which character encodings are accepted by the application/system] The attacker then needs to provide various character encodings to the application/system and determine which ones are accepted. The attacker will need to observe the application's/system's response to the encoded data to determine whether the data was interpreted properly. | techniques: Determine whi…
- Step 3 (Experiment): [Combine multiple encodings accepted by the application.] The attacker now combines encodings accepted by the application. The attacker may combine different encodings or apply the same encoding multiple times. | techniques: Combine same encoding multiple times and observe its effects. For example, if special characters are encoded with a leading backslash, then the following…
- Step 4 (Exploit): [Leverage ability to bypass input validation] Attacker leverages their ability to bypass input validation to gain unauthorized access to system. There are many attacks possible, and a few examples are mentioned here. | techniques: Gain access to sensitive files.; Perform command injection.; Perform SQL injection.; Perform XSS attacks.

## Prerequisites

- User input is used to construct a command to be executed on the target system or as part of the file name.
- Multiple parser passes are performed on the data supplied by the user.

## Skills required

- Medium: Knowledge of various escaping schemes, such as URL escape encoding and XML escape characters.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data

## Mitigations to bypass

- An iterative approach to input validation may be required to ensure that no dangerous characters are present. It may be necessary to implement redundant checking across different input validation layers. Ensure that invalid data is rejected as soon as possible and do not continue to work with it.
- Make sure to perform input validation on canonicalized data (i.e. data that is data in its most standard form). This will help avoid tricky encodings getting past the filters.
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist would not be permitted to enter into the system.

## Example instances (payload / topology hints)

- The backslash character provides a good example of the multiple-parser issue. A backslash is used to escape characters in strings, but is also used to delimit directories on the NT file system. When performing a command injection that includes NT paths, there is usually a need to "double escape" the backslash. In some cases, a quadruple escape is necessary. Original String: C:\\\\winnt\\\\system3…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-267](CAPEC-267.md)

## Related CWEs (run the cwe skill)

- [CWE-179](../cwe/references/CWE-179.md) — run that CWE procedure after this CAPEC flow
- [CWE-181](../cwe/references/CWE-181.md) — run that CWE procedure after this CAPEC flow
- [CWE-184](../cwe/references/CWE-184.md) — run that CWE procedure after this CAPEC flow
- [CWE-183](../cwe/references/CWE-183.md) — run that CWE procedure after this CAPEC flow
- [CWE-77](../cwe/references/CWE-77.md) — run that CWE procedure after this CAPEC flow
- [CWE-78](../cwe/references/CWE-78.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow
- [CWE-707](../cwe/references/CWE-707.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-43 and CWE IDs
