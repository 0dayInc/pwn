# CAPEC-38: Leveraging/Manipulating Configuration File Search Paths

- Catalog: [CAPEC-38](https://capec.mitre.org/data/definitions/38.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

This pattern of attack sees an adversary load a malicious resource into a program's standard path so that when a known command is executed then the system instead executes the malicious component. The adversary can either modify the search path a program uses, like a PATH variable or classpath, or they can manipulate resources on the path to point to their malicious components. J2EE applications and other component based applications that are built from multiple binaries can have very long list of dependencies to execute. If one of these libraries and/or references is controllable by the attacker then application controls can be circumvented by the attacker.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-38 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-38 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-38`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The attacker must be able to write to redirect search paths on the victim host.

## Skills required

- Low: To identify and execute against an over-privileged system interface

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Design: Enforce principle of least privilege
- Design: Ensure that the program's compound parts, including all system dependencies, classpath, path, and so on, are secured to the same or higher level assurance as the program
- Implementation: Host integrity monitoring

## Example instances (payload / topology hints)

- Another method is to redirect commands by aliasing one legitimate command to another to create unexpected results. the Unix command "rm" could be aliased to "mv" and move all files the victim thinks they are deleting to a directory the attacker controls. In a Unix shell .profile setting alias rm=mv /usr/home/attacker In this case the attacker retains a copy of all the files the victim attempts to…
- A standard UNIX path looks similar to this /bin:/sbin:/usr/bin:/usr/local/bin:/usr/sbin If the attacker modifies the path variable to point to a locale that includes malicious resources then the user unwittingly can execute commands on the attackers' behalf: /evildir/bin:/sbin:/usr/bin:/usr/local/bin:/usr/sbin This is a form of usurping control of the program and the attack can be done on the cla…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-159](CAPEC-159.md)

## Related CWEs (run the cwe skill)

- [CWE-426](../cwe/references/CWE-426.md) — run that CWE procedure after this CAPEC flow
- [CWE-427](../cwe/references/CWE-427.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-38 and CWE IDs
