# CAPEC-42: MIME Conversion

- Catalog: [CAPEC-42](https://capec.mitre.org/data/definitions/42.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker exploits a weakness in the MIME conversion routine to cause a buffer overflow and gain control over the mail server machine. The MIME system is designed to allow various different information formats to be interpreted and sent via e-mail. Attack points exist when data are converted to MIME compatible format and back.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-42 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST BannedFunctionCallsC / UseAfterFree, PWN::Plugins::Assembly

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-42 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-42`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target mail server] The adversary identifies a target mail server that they wish to attack. | techniques: Use Nmap on a system to identify a mail server service.
- Step 2 (Explore): [Determine viability of attack] Determine whether the mail server is unpatched and is potentially vulnerable to one of the known MIME conversion buffer overflows (e.g. Sendmail 8.8.3 and 8.8.4).
- Step 3 (Experiment): [Find injection vector] Identify places in the system where vulnerable MIME conversion routines may be used.
- Step 4 (Experiment): [Craft overflow content] The adversary crafts e-mail messages with special headers that will cause a buffer overflow for the vulnerable MIME conversion routine. The intent of this attack is to leverage the overflow for execution of arbitrary code and gain access to the mail server machine, so the adversary will craft an email that not only overflows the targeted buffer but do…
- Step 4 (Exploit): [Overflow the buffer] Send e-mail messages to the target system with specially crafted headers that trigger the buffer overflow and execute the shell code.

## Prerequisites

- The target system uses a mail server.
- Mail server vendor has not released a patch for the MIME conversion routine, the patch itself has a security hole or does not fix the original problem, or the patch has not been applied to the user's system.

## Skills required

- Low: It may be trivial to cause a DoS via this attack pattern
- High: Causing arbitrary code to execute on the target system.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Integrity: Modify Data
- Availability: Unreliable Execution
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Stay up to date with third party vendor patches
- Disable the 7 to 8 bit conversion. This can be done by removing the F=9 flag from all Mailer specifications in the sendmail.cf file. For example, a sendmail.cf file with these changes applied should look similar to (depending on your system and configuration): Mlocal, P=/usr/libexec/mail.local, F=lsDFMAw5:/|@qrmn, S=10/30, R=20/40, T=DNS/RFC822/X-Unix, A=mail -d $u Mprog, P=/bin/sh, F=lsDFMoqeu,…
- Use the sendmail restricted shell program (smrsh)
- Use mail.local

## Example instances (payload / topology hints)

- A MIME conversion buffer overflow exists in Sendmail versions 8.8.3 and 8.8.4. Sendmail versions 8.8.3 and 8.8.4 are vulnerable to a buffer overflow in the MIME handling code. By sending a message with specially-crafted headers to the server, a remote attacker can overflow a buffer and execute arbitrary commands on the system with root privileges. Sendmail performs a 7 bit to 8 bit conversion on…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-100](CAPEC-100.md)

## Related CWEs (run the cwe skill)

- [CWE-120](../cwe/references/CWE-120.md) — run that CWE procedure after this CAPEC flow
- [CWE-119](../cwe/references/CWE-119.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-42 and CWE IDs
