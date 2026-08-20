# CAPEC-50: Password Recovery Exploitation

- Catalog: [CAPEC-50](https://capec.mitre.org/data/definitions/50.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker may take advantage of the application feature to help users recover their forgotten passwords in order to gain access into the system with the same privileges as the original user. Generally password recovery schemes tend to be weak and insecure.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-50 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-50 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-50`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): Understand the password recovery mechanism and how it works.
- Step 2 (Exploit): Find a weakness in the password recovery mechanism and exploit it. For instance, a weakness may be that a standard single security question is used with an easy to determine answer.

## Prerequisites

- The system allows users to recover their passwords and gain access back into the system.
- Password recovery mechanism has been designed or implemented insecurely.
- Password recovery mechanism relies only on something the user knows and not something the user has.
- No third party intervention is required to use the password recovery mechanism.

## Skills required

- Low: Brute force attack
- Medium: Social engineering and more sophisticated technical attacks.

## Resources required

- For a brute force attack one would need a machine with sufficient CPU, RAM and HD.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Use multiple security questions (e.g. have three and make the user answer two of them correctly). Let the user select their own security questions or provide them with choices of questions that are not generic.
- E-mail the temporary password to the registered e-mail address of the user rather than letting the user reset the password online.
- Ensure that your password recovery functionality is not vulnerable to an injection style attack.

## Example instances (payload / topology hints)

- An attacker clicks on the "forgot password" and is presented with a single security question. The question is regarding the name of the first dog of the user. The system does not limit the number of attempts to provide the dog's name. An attacker goes through a list of 100 most popular dog names and finds the right name, thus getting the ability to reset the password and access the system.
- phpBanner Exchange is a PHP script (using the mySQL database) that facilitates the running of a banner exchange without extensive knowledge of PHP or mySQL. A SQL injection was discovered in the password recovery module of the system that allows recovering an arbitrary user's password and taking over their account. The problem is due to faulty input sanitization in the phpBannerExchange, specific…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-212](CAPEC-212.md)
- CanPrecede → [CAPEC-600](CAPEC-600.md)
- CanPrecede → [CAPEC-151](CAPEC-151.md)
- CanPrecede → [CAPEC-560](CAPEC-560.md)
- CanPrecede → [CAPEC-561](CAPEC-561.md)
- CanPrecede → [CAPEC-653](CAPEC-653.md)

## Related CWEs (run the cwe skill)

- [CWE-522](../cwe/references/CWE-522.md) — run that CWE procedure after this CAPEC flow
- [CWE-640](../cwe/references/CWE-640.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-50 and CWE IDs
