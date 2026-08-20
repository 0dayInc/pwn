# CAPEC-460: HTTP Parameter Pollution (HPP)

- Catalog: [CAPEC-460](https://capec.mitre.org/data/definitions/460.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary adds duplicate HTTP GET/POST parameters by injecting query string delimiters. Via HPP it may be possible to override existing hardcoded HTTP parameters, modify the application behaviors, access and, potentially exploit, uncontrollable variables, and bypass input validation checkpoints and WAF rules.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-460 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-460 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-460`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find User Input] The adversary finds anywhere in the web application that uses user-supplied input in a form or action. This can also be found by looking at parameters in the URL in the navigation bar of the browser
- Step 2 (Experiment): [Add Duplicate Parameter Values] Once the adversary has identified what user input is used as HTTP parameters, they will add duplicates to each parameter one by one to observe the results. If the response from the HTTP request shows the duplicate parameter value concatenated with the original parameter value in some way, or simply just the duplicate parameter value, then HPP…
- Step 3 (Exploit): [Leverage HPP] Once the adversary has identified how the backend handles duplicate parameters, they will leverage this by polluting the paramters in a way that benefits them. In some cases, hardcoded parameters will be disregarded by the backend. In others, the adversary can bypass a WAF that might only check a parameter before it has been concatenated by the backend, resulting…

## Prerequisites

- HTTP protocol is used with some GET/POST parameters passed

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- Any tool that enables intercepting and tampering with HTTP requests

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Configuration: If using a Web Application Firewall (WAF), filters should be carefully configured to detect abnormal HTTP requests
- Design: Perform URL encoding
- Implementation: Use strict regular expressions in URL rewriting
- Implementation: Beware of multiple occurrences of a parameter in a Query String

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-15](CAPEC-15.md)
- CanPrecede → [CAPEC-676](CAPEC-676.md)

## Related CWEs (run the cwe skill)

- [CWE-88](../cwe/references/CWE-88.md) — run that CWE procedure after this CAPEC flow
- [CWE-147](../cwe/references/CWE-147.md) — run that CWE procedure after this CAPEC flow
- [CWE-235](../cwe/references/CWE-235.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-460 and CWE IDs
