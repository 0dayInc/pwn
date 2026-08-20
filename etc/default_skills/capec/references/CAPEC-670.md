# CAPEC-670: Software Development Tools Maliciously Altered

- Catalog: [CAPEC-670](https://capec.mitre.org/data/definitions/670.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary with the ability to alter tools used in a development environment causes software to be developed with maliciously modified tools. Such tools include requirements management and database tools, software design tools, configuration management tools, compilers, system build tools, and software performance testing and load testing tools. The adversary then carries out malicious acts once the software is deployed including malware infection of other systems to support further compromises.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-670 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-670 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-670`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- An adversary would need to have access to a targeted developer’s development environment and in particular to tools used to design, create, test and manage software, where the adversary could ensure malicious code is included in software packages built through alteration or substitution of tools in the environment used in the development of software.

## Skills required

- High: Ability to leverage common delivery mechanisms (e.g., email attachments, removable media) to infiltrate a development environment to gain access to software development tools for the purpose of malware insertion into an existing tool or replacement of an existing tool with a maliciously altered cop…

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Execute Unauthorized Commands
- Access Control: Gain Privileges
- Confidentiality: Modify Data, Read Data

## Mitigations to bypass

- Have a security concept of operations (CONOPS) for the development environment that includes: Maintaining strict security administration and configuration management of requirements management and database tools, software design tools, configuration management tools, compilers, system build tools, and software performance testing and load testing tools.
- Avoid giving elevated privileges to developers.

## Example instances (payload / topology hints)

- An adversary with access to software build tools inside an Integrated Development Environment IDE alters a script used for downloading dependencies from a dependent code repository where the script has been changed to include malicious code implanted in the repository by the adversary.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-444](CAPEC-444.md)
- CanPrecede → [CAPEC-669](CAPEC-669.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-670 and CWE IDs
