# CAPEC-251: Local Code Inclusion

- Catalog: [CAPEC-251](https://capec.mitre.org/data/definitions/251.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

The attacker forces an application to load arbitrary code files from the local machine. The attacker could use this to try to load old versions of library files that have known vulnerabilities, to load files that the attacker placed on the local machine during a prior attack, or to otherwise change the functionality of the targeted application in unexpected ways.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-251 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-251 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-251`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The targeted application must have a bug that allows an adversary to control which code file is loaded at some juncture.
- Some variants of this attack may require that old versions of some code files be present and in predictable locations.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- The adversary needs to have enough access to the target application to control the identity of a locally included file. The attacker may also need to be able to upload arbitrary code files to the target machine, although any location for these files may be acceptable.

## Oracles (consequences)

- Integrity: Execute Unauthorized Commands — Through local code inclusion, the adversary compromises the integrity of the application.
- Confidentiality: Read Data — An attacker may leverage local code inclusion in order to print sensitive data to a page, such as hidden configuration files or or password hashes.

## Mitigations to bypass

- Implementation: Avoid passing user input to filesystem or framework API. If necessary to do so, implement a specific, allowlist approach.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-175](CAPEC-175.md)

## Related CWEs (run the cwe skill)

- [CWE-829](../cwe/references/CWE-829.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-251 and CWE IDs
