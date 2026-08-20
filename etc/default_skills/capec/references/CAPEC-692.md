# CAPEC-692: Spoof Version Control System Commit Metadata

- Catalog: [CAPEC-692](https://capec.mitre.org/data/definitions/692.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary spoofs metadata pertaining to a Version Control System (VCS) (e.g., Git) repository's commits to deceive users into believing that the maliciously provided software is frequently maintained and originates from a trusted source.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-692 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-692 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-692`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target] The adversary must first identify a target repository for them to spoof. Typically, this will be a popular and widely used repository, as to increase the amount of victims a successful attack will exploit.
- Step 2 (Experiment): [Create malicious repository] The adversary must create a malicious repository that imitates the legitimate repository being spoofed. This may include creating a username that closely matches the legitimate repository owner; creating a repository name that closely matches the legitimate repository name; uploading the legitimate source code; and more.
- Step 3 (Experiment): [Spoof commit metadata] Once the malicious repository has been created, the adversary must then spoof the commit metadata to make the repository appear to be frequently maintained and originating from trusted sources. | techniques: Git Commit Timestamps: The adversary generates numerous fake commits while setting the "GIT_AUTHOR_DATE" and "GIT_COMMITTER_DATE" environment vari…
- Step 4 (Exploit): [Exploit victims] The adversary infiltrates software and/or system environments with the goal of conducting additional attacks. | techniques: Active: The adversary attempts to trick victims into downloading the malicious software by means such as phishing and social engineering.; Passive: The adversary waits for victims to download and leverage malicious software.

## Prerequisites

- Identification of a popular open-source repository whose metadata is to be spoofed.

## Skills required

- Medium: Ability to spoof a variety of repository metadata to convince victims the source is trusted.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Accountability: Hide Activities
- Access Control, Authorization: Execute Unauthorized Commands, Alter Execution Logic, Gain Privileges

## Mitigations to bypass

- Before downloading open-source software, perform precursory metadata checks to determine the author(s), frequency of updates, when the software was last updated, and if the software is widely leveraged.
- Reference vulnerability databases to determine if the software contains known vulnerabilities.
- Only download open-source software from reputable hosting sites or package managers.
- Only download open-source software that has been adequately signed by the developer(s). For repository commits/tags, look for the "Verified" status and for developers leveraging "Vigilant Mode" (GitHub) or similar modes.
- After downloading open-source software, ensure integrity values have not changed.
- Before executing or incorporating the software, leverage automated testing techniques (e.g., static and dynamic analysis) to determine if the software behaves maliciously.

## Example instances (payload / topology hints)

- In July 2022, Checkmarx reported that GitHub commit metadata could be spoofed if unsigned commits were leveraged by the repository. Adversaries were able to spoof commit contributors, as well as the date/time of the commit. This resulted in commits appearing to originate from trusted developers and a GitHub activity graph that duped users into believing that the repository had been maintained for…

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
- [ ] Finding (if any) cites CAPEC-692 and CWE IDs
