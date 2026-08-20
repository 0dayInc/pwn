# CAPEC-155: Screen Temporary Files for Sensitive Information

- Catalog: [CAPEC-155](https://capec.mitre.org/data/definitions/155.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary exploits the temporary, insecure storage of information by monitoring the content of files used to store temp data during an application's routine execution flow. Many applications use temporary files to accelerate processing or to provide records of state across multiple executions of the application. Sometimes, however, these temporary files may end up storing sensitive information. By screening an application's temporary files, an adversary might be able to discover such sensitive information. For example, web browsers often cache content to accelerate subsequent lookups. If the content contains sensitive information then the adversary could recover this from the web cache.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-155 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-155 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-155`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Look for temporary files in target application] An adversary will try to discover temporary files in a target application. Knowledge of where the temporary files are being stored is important information.
- Step 2 (Experiment): [Attempt to read temporary files] An adversary will attempt to read any temporary files they may have discovered through normal means. | techniques: Attempt to get the file by querying the file path to a web server; Using a remote shell into an application, read temporary files and send out information remotely if necessary; Recover temporary information from a user's browser…
- Step 3 (Exploit): [Use function weaknesses to gain access to temporary files] If normal means to read temporary files did not work, an adversary will attempt to exploit weak temporary file functions to gain access to temporary files. | techniques: Some C functions such as tmpnam(), tempnam(), and mktemp() will create a temporary file with a unique name, but do not stop an adversary from creating…

## Prerequisites

- The target application must utilize temporary files and must fail to adequately secure them against other parties reading them.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- Because some application may have a large number of temporary files and/or these temporary files may be very large, an adversary may need tools that help them quickly search these files for sensitive information. If the adversary can simply copy the files to another location and if the speed of the search is not important, the adversary can still perform the attack without any special resources.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-150](CAPEC-150.md)

## Related CWEs (run the cwe skill)

- [CWE-377](../cwe/references/CWE-377.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-155 and CWE IDs
