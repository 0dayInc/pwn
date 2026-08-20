# CAPEC-693: StarJacking

- Catalog: [CAPEC-693](https://capec.mitre.org/data/definitions/693.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary spoofs software popularity metadata to deceive users into believing that a maliciously provided package is widely used and originates from a trusted source.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-693 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-693 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-693`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target] The adversary must first identify a target package whose popularity statistics will be leveraged. This will be a popular and widely used package, as to increase the perceived pedigree of the malicious package.
- Step 2 (Experiment): [Spoof package popularity] The adversary provides their malicious package to a package manager and uses the source code repository URL identified in Step 1 to spoof the popularity of the package. This malicious package may also closely resemble the legitimate package whose statistics are being utilized.
- Step 3 (Exploit): [Exploit victims] The adversary infiltrates development environments with the goal of conducting additional attacks. | techniques: Active: The adversary attempts to trick victims into downloading the malicious package by means such as phishing and social engineering.; Passive: The adversary waits for victims to download and leverage the malicious package.

## Prerequisites

- Identification of a popular open-source package whose popularity metadata is to be used for the malicious package.

## Skills required

- Low: Ability to provide a package to a package manager and associate a popular package's source code repository URL.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Accountability: Hide Activities
- Access Control, Authorization: Execute Unauthorized Commands, Alter Execution Logic, Gain Privileges

## Mitigations to bypass

- Before downloading open-source packages, perform precursory metadata checks to determine the author(s), frequency of updates, when the software was last updated, and if the software is widely leveraged.
- Look for conflicting or non-unique repository references to determine if multiple packages share the same repository reference.
- Reference vulnerability databases to determine if the software contains known vulnerabilities.
- Only download open-source packages from reputable package managers.
- After downloading open-source packages, ensure integrity values have not changed.
- Before executing or incorporating the package, leverage automated testing techniques (e.g., static and dynamic analysis) to determine if the software behaves maliciously.

## Example instances (payload / topology hints)

- In April 2022, Checkmarx reported that packages hosted on NPM, PyPi, and Yarn do not properly validate that the provided GitHub repository URL actually pertains to the package being provided. Combined with additional attacks such as TypoSquatting, this allows adversaries to spoof popularity metadata by associating popular GitHub repository URLs with the malicious package. This can further lead to…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-691](CAPEC-691.md)

## Related CWEs (run the cwe skill)

- [CWE-494](../cwe/references/CWE-494.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-693 and CWE IDs
