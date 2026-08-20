# CAPEC-41: Using Meta-characters in E-mail Headers to Inject Malicious Payloads

- Catalog: [CAPEC-41](https://capec.mitre.org/data/definitions/41.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This type of attack involves an attacker leveraging meta-characters in email headers to inject improper behavior into email programs. Email software has become increasingly sophisticated and feature-rich. In addition, email applications are ubiquitous and connected directly to the Web making them ideal targets to launch and propagate attacks. As the user demand for new functionality in email applications grows, they become more like browsers with complex rendering and plug in routines. As more email functionality is included and abstracted from the user, this creates opportunities for attackers. Virtually all email applications do not list email header information by default, however the email header contains valuable attacker vectors for the attacker to exploit particularly if the behavior of the email client application is known. Meta-characters are hidden from the user, but can contain scripts, enumerations, probes, and other attacks against the user's system.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-41 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-41 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-41`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Experiment): [Identify and characterize metacharacter-processing vulnerabilities in email headers] An attacker creates emails with headers containing various metacharacter-based malicious payloads in order to determine whether the target application processes the malicious content and in what manner it does so. | techniques: Use an automated tool (fuzzer) to create malicious emails header…
- Step 2 (Exploit): An attacker leverages vulnerabilities identified during the Experiment Phase to inject malicious email headers and cause the targeted email application to exhibit behavior outside of its expected constraints. | techniques: Send emails with specifically-constructed, metacharacter-based malicious payloads in the email headers to targeted systems running email processing applicatio…

## Prerequisites

- This attack targets most widely deployed feature rich email applications, including web based email programs.

## Skills required

- Low: To distribute email

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Design: Perform validation on email header data
- Implementation: Implement email filtering solutions on mail server or on MTA, relay server.
- Implementation: Mail servers that perform strict validation may catch these attacks, because metacharacters are not allowed in many header variables such as dns names

## Example instances (payload / topology hints)

- To:<someone@example.com> From:<badguy@example.com> Header<SCRIPT>payme</SCRIPT>def: whatever
- Meta-characters are among the most valuable tools attackers have to deceive users into taking some action on their behalf. E-mail is perhaps the most efficient and cost effective attack distribution tool available, this has led to the phishing pandemic. Meta-characters like \w \s \d ^ can allow the attacker to escape out of the expected behavior to execute additional commands. Escaping out the pr…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-242](CAPEC-242.md)
- ChildOf → [CAPEC-134](CAPEC-134.md)

## Related CWEs (run the cwe skill)

- [CWE-150](../cwe/references/CWE-150.md) — run that CWE procedure after this CAPEC flow
- [CWE-88](../cwe/references/CWE-88.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-41 and CWE IDs
