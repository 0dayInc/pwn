# CAPEC-267: Leverage Alternate Encoding

- Catalog: [CAPEC-267](https://capec.mitre.org/data/definitions/267.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary leverages the possibility to encode potentially harmful input or content used by applications such that the applications are ineffective at validating this encoding standard.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-267 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-267 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-267`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for user-controllable inputs] Using a browser, an automated tool or by inspecting the application, an adversary records all entry points to the application. | techniques: Use a spidering tool to follow and record all links and analyze the web pages to find entry points. Make special note of any links that include parameters in the URL.; Use a proxy tool t…
- Step 2 (Experiment): [Probe entry points to locate vulnerabilities] The adversary uses the entry points gathered in the "Explore" phase as a target list and injects various payloads using a variety of different types of encodings to determine if an entry point actually represents a vulnerability with insufficient validation logic and to characterize the extent to which the vulnerability can be ex…

## Prerequisites

- The application's decoder accepts and interprets encoded characters. Data canonicalization, input filtering and validating is not done properly leaving the door open to harmful characters for the target host.

## Skills required

- Low: An adversary can inject different representation of a filtered character in a different encoding.
- Medium: An adversary may craft subtle encoding of input data by using the knowledge that they have gathered about the target host.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism
- Availability: Unreliable Execution, Resource Consumption — Denial of Service

## Mitigations to bypass

- Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system. Test your decoding process against malicious input.

## Example instances (payload / topology hints)

- Microsoft Internet Explorer 5.01 SP4, 6, 6 SP1, and 7 does not properly handle unspecified "encoding strings," which allows remote adversaries to bypass the Same Origin Policy and obtain sensitive information via a crafted web site, aka "Post Encoding Information Disclosure Vulnerability." Related Vulnerabilities CVE-2010-0488
- Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-153](CAPEC-153.md)

## Related CWEs (run the cwe skill)

- [CWE-173](../cwe/references/CWE-173.md) — run that CWE procedure after this CAPEC flow
- [CWE-172](../cwe/references/CWE-172.md) — run that CWE procedure after this CAPEC flow
- [CWE-180](../cwe/references/CWE-180.md) — run that CWE procedure after this CAPEC flow
- [CWE-181](../cwe/references/CWE-181.md) — run that CWE procedure after this CAPEC flow
- [CWE-73](../cwe/references/CWE-73.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow
- [CWE-692](../cwe/references/CWE-692.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-267 and CWE IDs
