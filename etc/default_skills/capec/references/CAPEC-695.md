# CAPEC-695: Repo Jacking

- Catalog: [CAPEC-695](https://capec.mitre.org/data/definitions/695.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary takes advantage of the redirect property of directly linked Version Control System (VCS) repositories to trick users into incorporating malicious code into their applications.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-695 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::TransparentBrowser, PWN::Plugins::URIScheme

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-695 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-695`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target] The adversary must first identify a target repository that is commonly used and whose owner/maintainer has either changed/deleted their username or transferred ownership of the repository and then deleted their account. The target should typically be a popular and widely used package, as to increase the scope of the attack.
- Step 2 (Experiment): [Recreate initial repository path] The adversary re-registers the account that was renamed/deleted by the target repository's owner/maintainer and recreates the target repository with malicious code intended to exploit an application. These steps may need to happen in reverse (i.e., recreate repository and then rename an existing account to the target account) if protections…
- Step 3 (Exploit): [Exploit victims] The adversary's malicious code is incorporated into applications that directly reference the initial repository, which further allows the adversary to conduct additional attacks.

## Prerequisites

- Identification of a popular repository that may be directly referenced in numerous software applications
- A repository owner/maintainer who has recently changed their username or deleted their account

## Skills required

- Low: Ability to create an account on a VCS hosting site and recreate an existing directory structure.
- Low: Ability to create malware that can exploit various software applications.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Read Data, Modify Data
- Access Control, Authorization: Execute Unauthorized Commands, Alter Execution Logic, Gain Privileges

## Mitigations to bypass

- Leverage dedicated package managers instead of directly linking to VCS repositories.
- Utilize version pinning and lock files to prevent use of maliciously modified repositories.
- Implement "vendoring" (i.e., including third-party dependencies locally) and leverage automated testing techniques (e.g., static analysis) to determine if the software behaves maliciously.
- Leverage automated tools, such as Checkmarx's "ChainJacking" tool, to determine susceptibility to Repo Jacking attacks.

## Example instances (payload / topology hints)

- In May 2022, the CTX Python package and PhPass PHP package were both exploited by the same adversary via Repo Jacking attacks. For the CTX package, the adversary performed an account takeover via a password reset, due to an expired domain-hosting email. The attack on PhPass entailed bypassing GitHub's authentication for retired repositories. In both cases, sensitive data in the form of API keys a…
- In October 2021, the popular JavaScript library UAParser.js was exploited via the takeover of the author's Node Package Manager (NPM) account. The adversary-provided malware downloaded and executed binaries from a remote server to conduct crypto-mining and to exfiltrate sensitive data on Windows systems. This was a wide-scale attack as the package receives 8 to 9 million downloads per week. [REF-…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-616](CAPEC-616.md)

## Related CWEs (run the cwe skill)

- [CWE-494](../cwe/references/CWE-494.md) — run that CWE procedure after this CAPEC flow
- [CWE-829](../cwe/references/CWE-829.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-695 and CWE IDs
