# CAPEC-53: Postfix, Null Terminate, and Backslash

- Catalog: [CAPEC-53](https://capec.mitre.org/data/definitions/53.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

If a string is passed through a filter of some kind, then a terminal NULL may not be valid. Using alternate representation of NULL allows an adversary to embed the NULL mid-string while postfixing the proper data so that the filter is avoided. One example is a filter that looks for a trailing slash character. If a string insertion is possible, but the slash must exist, an alternate encoding of NULL in mid-string may be used.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-53 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-53 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-53`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for user-controllable inputs] Using a browser, an automated tool or by inspecting the application, an adversary records all entry points to the application. | techniques: Use a spidering tool to follow and record all links and analyze the web pages to find entry points. Make special note of any links that include parameters in the URL.; Use a proxy tool t…
- Step 2 (Experiment): [Probe entry points to locate vulnerabilities] The adversary uses the entry points gathered in the "Explore" phase as a target list and injects postfix null byte(s) followed by a backslash to observe how the application handles them as input. The adversary is looking for areas where user input is placed in the middle of a string, and the null byte causes the application to st…
- Step 3 (Exploit): [Remove data after null byte(s)] After determined entry points that are vulnerable, the adversary places a null byte(s) followed by a backslash such that they bypass an input filter and remove data after the null byte(s) in a way that is beneficial to them. | techniques: If the input is a directory as part of a longer file path, add a null byte(s) followed by a backslash at the…

## Prerequisites

- Null terminators are not properly handled by the filter.

## Skills required

- Medium: An adversary needs to understand alternate encodings, what the filter looks for and the data format acceptable to the target API

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Properly handle Null characters. Make sure canonicalization is properly applied. Do not pass Null characters to the underlying APIs.
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system.

## Example instances (payload / topology hints)

- A rather simple injection is possible in a URL: http://getAccessHostname/sekbin/ helpwin.gas.bat?mode=&draw=x&file=x&module=&locale=[insert relative path here] [%00][%5C]&chapter= This attack has appeared with regularity in the wild. There are many variations of this kind of attack. Spending a short amount of time injecting against Web applications will usually result in a new exploit being disco…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-267](CAPEC-267.md)

## Related CWEs (run the cwe skill)

- [CWE-158](../cwe/references/CWE-158.md) — run that CWE procedure after this CAPEC flow
- [CWE-172](../cwe/references/CWE-172.md) — run that CWE procedure after this CAPEC flow
- [CWE-173](../cwe/references/CWE-173.md) — run that CWE procedure after this CAPEC flow
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
- [ ] Finding (if any) cites CAPEC-53 and CWE IDs
