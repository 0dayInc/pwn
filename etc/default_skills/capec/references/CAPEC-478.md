# CAPEC-478: Modification of Windows Service Configuration

- Catalog: [CAPEC-478](https://capec.mitre.org/data/definitions/478.html)
- Abstraction: Detailed · Status: Usable
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits a weakness in access control to modify the execution parameters of a Windows service. The goal of this attack is to execute a malicious binary in place of an existing service.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-478 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-478 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-478`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine target system] The adversary must first determine the system they wish to modify the registry of. This needs to be a windows machine as this attack only works on the windows registry.
- Step 2 (Experiment): [Gain access to the system] The adversary needs to gain access to the system in some way so that they can modify the windows registry. | techniques: Gain physical access to a system either through shoulder surfing a password or accessing a system that is left unlocked.; Gain remote access to a system through a variety of means.
- Step 3 (Exploit): [Modify windows registry] The adversary will modify the windows registry by changing the configuration settings for a service. Specifically, the adversary will change the path settings to define a path to a malicious binary to be executed.

## Prerequisites

- The adversary must have the capability to write to the Windows Registry on the targeted system.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Integrity: Execute Unauthorized Commands — By altering specific configuration settings for the service, the adversary could run arbitrary code to be executed.

## Mitigations to bypass

- Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-203](CAPEC-203.md)

## Related CWEs (run the cwe skill)

- [CWE-284](../cwe/references/CWE-284.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-478 and CWE IDs
