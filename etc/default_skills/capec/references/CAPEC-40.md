# CAPEC-40: Manipulating Writeable Terminal Devices

- Catalog: [CAPEC-40](https://capec.mitre.org/data/definitions/40.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

This attack exploits terminal devices that allow themselves to be written to by other users. The attacker sends command strings to the target terminal device hoping that the target user will hit enter and thereby execute the malicious command with their privileges. The attacker can send the results (such as copying /etc/passwd) to a known directory and collect once the attack has succeeded.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-40 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-40 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-40`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify attacker-writable terminals] Determine if users TTYs are writable by the attacker. | techniques: Determine the permissions for the TTYs found on the system. Any that allow user write to the TTY may be vulnerable.; Attempt to write to other user TTYs. This approach could leave a trail or alert a user.
- Step 2 (Exploit): [Execute malicious commands] Using one or more vulnerable TTY, execute commands to achieve various impacts. | techniques: Commands that allow reading or writing end user files can be executed.

## Prerequisites

- User terminals must have a permissive access control such as world writeable that allows normal users to control data on other user's terminals.

## Skills required

- Low: Ability to discover permissions on terminal devices. Of course, brute force can also be used.

## Resources required

- Access to a terminal on the target network

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Design: Ensure that terminals are only writeable by named owner user and/or administrator
- Design: Enforce principle of least privilege

## Example instances (payload / topology hints)

- "Any system that allows other peers to write directly to its terminal process is vulnerable to this type of attack. If the terminals are available through being over-privileged (i.e. world-writable) or the attacker is an administrator, then a series of commands in this format can be used to echo commands out to victim terminals. "$echo -e "\033[30m\033\132" > /dev/ttyXX where XX is the tty number…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-248](CAPEC-248.md)

## Related CWEs (run the cwe skill)

- [CWE-77](../cwe/references/CWE-77.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-40 and CWE IDs
