# CAPEC-81: Web Server Logs Tampering

- Catalog: [CAPEC-81](https://capec.mitre.org/data/definitions/81.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

Web Logs Tampering attacks involve an attacker injecting, deleting or otherwise tampering with the contents of web logs typically for the purposes of masking other malicious behavior. Additionally, writing malicious data to log files may target jobs, filters, reports, and other agents that process the logs in an asynchronous attack pattern. This pattern of attack is similar to "Log Injection-Tampering-Forging" except that in this case, the attack is targeting the logs of the web server and not the application.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-81 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-81 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-81`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine Application Web Server Log File Format] The attacker observes the system and looks for indicators of which logging utility is being used by the web server. | techniques: Determine logging utility being used by application web server (e.g. log4j), only possible if the application is known by the attacker or if the application returns error messages with logging utility…
- Step 2 (Experiment): [Determine Injectable Content] The attacker launches various logged actions with malicious data to determine what sort of log injection is possible. | techniques: Attacker triggers logged actions with maliciously crafted data as inputs, parameters, arguments, etc.
- Step 3 (Exploit): [Manipulate Log Files] The attacker alters the log contents either directly through manipulation or forging or indirectly through injection of specially crafted request that the web server will receive and write into the logs. This type of attack typically follows another attack and is used to try to cover the traces of the previous attack. | techniques: Indirectly through injec…

## Prerequisites

- Target server software must be a HTTP server that performs web logging.

## Skills required

- Low: To input faked entries into Web logs

## Resources required

- Ability to send specially formatted HTTP request to web server

## Oracles (consequences)

- Integrity: Modify Data

## Mitigations to bypass

- Design: Use input validation before writing to web log
- Design: Validate all log data before it is output

## Example instances (payload / topology hints)

- Most web servers have a public interface, even if the majority of the site is password protected, there is usually at least a login site and brochureware that is publicly available. HTTP requests to the site are also generally logged to a Web log. From an attacker point of view, standard HTTP requests containing a malicious payload can be sent to the public website (with no other access required)…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-268](CAPEC-268.md)

## Related CWEs (run the cwe skill)

- [CWE-117](../cwe/references/CWE-117.md) — run that CWE procedure after this CAPEC flow
- [CWE-93](../cwe/references/CWE-93.md) — run that CWE procedure after this CAPEC flow
- [CWE-75](../cwe/references/CWE-75.md) — run that CWE procedure after this CAPEC flow
- [CWE-221](../cwe/references/CWE-221.md) — run that CWE procedure after this CAPEC flow
- [CWE-96](../cwe/references/CWE-96.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-150](../cwe/references/CWE-150.md) — run that CWE procedure after this CAPEC flow
- [CWE-276](../cwe/references/CWE-276.md) — run that CWE procedure after this CAPEC flow
- [CWE-279](../cwe/references/CWE-279.md) — run that CWE procedure after this CAPEC flow
- [CWE-116](../cwe/references/CWE-116.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-81 and CWE IDs
