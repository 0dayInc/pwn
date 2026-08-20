# CAPEC-96: Block Access to Libraries

- Catalog: [CAPEC-96](https://capec.mitre.org/data/definitions/96.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An application typically makes calls to functions that are a part of libraries external to the application. These libraries may be part of the operating system or they may be third party libraries. It is possible that the application does not handle situations properly where access to these libraries has been blocked. Depending on the error handling within the application, blocked access to libraries may leave the system in an insecure state that could be leveraged by an attacker.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-96 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-96 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-96`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): Determine what external libraries the application accesses.
- Step 2 (Experiment): Block access to the external libraries accessed by the application.
- Step 3 (Experiment): Monitor the behavior of the system to see if it goes into an insecure/inconsistent state.
- Step 4 (Experiment): If the system does go into an insecure/inconsistent state, leverage that to obtain information about the system functionality or data, elevate access control, etc. The rest of this attack will depend on the context and the desired goal.

## Prerequisites

- An application requires access to external libraries.
- An attacker has the privileges to block application access to external libraries.

## Skills required

- Low: Knowledge of how to block access to libraries, as well as knowledge of how to leverage the resulting state of the application based on the failed call.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Availability: Alter Execution Logic
- Confidentiality: Other
- Confidentiality, Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Ensure that application handles situations where access to APIs in external libraries is not available securely. If the application cannot continue its execution safely it should fail in a consistent and secure fashion.

## Example instances (payload / topology hints)

- A web-based system uses a third party cryptographic random number generation library that derives entropy from machine's hardware. This library is used in generation of user session ids used by the application. If the library is inaccessible, the application instead uses a software based weak pseudo random number generation library. An attacker of the system blocks access of the application to th…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-603](CAPEC-603.md)

## Related CWEs (run the cwe skill)

- [CWE-589](../cwe/references/CWE-589.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-96 and CWE IDs
