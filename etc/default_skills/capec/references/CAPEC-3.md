# CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters

- Catalog: [CAPEC-3](https://capec.mitre.org/data/definitions/3.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

Some APIs will strip certain leading characters from a string of parameters. An adversary can intentionally introduce leading "ghost" characters (extra characters that don't affect the validity of the request at the API layer) that enable the input to pass the filters and therefore process the adversary's input. This occurs when the targeted API will accept input data in several syntactic forms and interpret it in the equivalent semantic way, while the filter does not take into account the full spectrum of the syntactic forms acceptable to the targeted API.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-3 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-3 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-3`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for user-controllable inputs] Using a browser, an automated tool or by inspecting the application, an adversary records all entry points to the application. | techniques: Use a spidering tool to follow and record all links and analyze the web pages to find entry points. Make special note of any links that include parameters in the URL.; Use a proxy tool t…
- Step 2 (Experiment): [Probe entry points to locate vulnerabilities] The adversary uses the entry points gathered in the "Explore" phase as a target list and injects various leading 'Ghost' character sequences to determine how to application filters them. | techniques: Add additional characters to common sequences such as "../" to see how the application will filter them.; Try repeating special ch…
- Step 3 (Exploit): [Bypass input filtering] Using what the adversary learned about how the application filters input data, they craft specific input data that bypasses the filter. This can lead to directory traversal attacks, arbitrary shell command execution, corruption of files, etc.

## Prerequisites

- The targeted API must ignore the leading ghost characters that are used to get past the filters for the semantics to be the same.

## Skills required

- Medium: The ability to make an API request, and knowledge of "ghost" characters that will not be filtered by any input validation. These "ghost" characters must be known to not affect the way in which the request will be interpreted.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Integrity: Modify Data

## Mitigations to bypass

- Use an allowlist rather than a denylist input validation.
- Canonicalize all data prior to validation.
- Take an iterative approach to input validation (defense in depth).

## Example instances (payload / topology hints)

- Alternate Encoding with Ghost Characters in FTP and Web Servers Some web and FTP servers fail to detect prohibited upward directory traversals if the user-supplied pathname contains extra characters such as an extra leading dot. For example, a program that will disallow access to the pathname "../test.txt" may erroneously allow access to that file if the pathname is specified as ".../test.txt". T…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-267](CAPEC-267.md)

## Related CWEs (run the cwe skill)

- [CWE-173](../cwe/references/CWE-173.md) — run that CWE procedure after this CAPEC flow
- [CWE-41](../cwe/references/CWE-41.md) — run that CWE procedure after this CAPEC flow
- [CWE-172](../cwe/references/CWE-172.md) — run that CWE procedure after this CAPEC flow
- [CWE-179](../cwe/references/CWE-179.md) — run that CWE procedure after this CAPEC flow
- [CWE-180](../cwe/references/CWE-180.md) — run that CWE procedure after this CAPEC flow
- [CWE-181](../cwe/references/CWE-181.md) — run that CWE procedure after this CAPEC flow
- [CWE-183](../cwe/references/CWE-183.md) — run that CWE procedure after this CAPEC flow
- [CWE-184](../cwe/references/CWE-184.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow
- [CWE-707](../cwe/references/CWE-707.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-3 and CWE IDs
