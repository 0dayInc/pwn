# CAPEC-538: Open-Source Library Manipulation

- Catalog: [CAPEC-538](https://capec.mitre.org/data/definitions/538.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

Adversaries implant malicious code in open source software (OSS) libraries to have it widely distributed, as OSS is commonly downloaded by developers and other users to incorporate into software development projects. The adversary can have a particular system in mind to target, or the implantation can be the first stage of follow-on attacks on many systems.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-538 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-538 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-538`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine the relevant open-source code project to target] The adversary will make the selection based on various criteria: The open-source code currently in use on a selected target system. The depth in the dependency graph of the open source code in relationship to other code bases in use on the target system. Choosing an OSS lower in the graph decreases the probability of di…
- Step 2 (Experiment): [Develop a plan for malicious contribution] The adversary develops a plan to contribute malicious code, taking the following into consideration: The adversary will probably avoid easy-to-find software weaknesses, especially ones that static and dynamic analysis tools are likely to discover. Common coding errors or missing edge cases of the algorithm, which can be explained aw…
- Step 3 (Exploit): [Execute the plan for malicious contribution] Write the code to be contributed based on the plan and then submit the contribution. Multiple commits, possibly using multiple identities, will help obscure the attack. Monitor the contribution site to try to determine if the code has been uploaded to the target system.

## Prerequisites

- Access to the open source code base being used by the manufacturer in a system being developed or currently deployed at a victim location.

## Skills required

- High: Advanced knowledge about the inclusion and specific usage of an open source code project within system being targeted for infiltration.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- An adversary with access to an open source code project introduces a hard-to-find bug in the software that allows under very specific conditions for encryption to be disabled on data streams. The adversary commits the change to the code which is picked up by a manufacturer who develops VPN software. It is eventually deployed at the victim's location where the very specific conditions are met givi…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-444](CAPEC-444.md)

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
- [ ] Finding (if any) cites CAPEC-538 and CWE IDs
