# CAPEC-270: Modification of Registry Run Keys

- Catalog: [CAPEC-270](https://capec.mitre.org/data/definitions/270.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary adds a new entry to the "run keys" in the Windows registry so that an application of their choosing is executed when a user logs in. In this way, the adversary can get their executable to operate and run on the target system with the authorized user's level of permissions. This attack is a good way for an adversary to run persistent spyware on a user's machine, such as a keylogger.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-270 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-270 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-270`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine target system] The adversary must first determine the system they wish to target. This attack only works on Windows.
- Step 2 (Experiment): [Gain access to the system] The adversary needs to gain access to the system in some way so that they can modify the Windows registry. | techniques: Gain physical access to a system either through shoulder surfing a password or accessing a system that is left unlocked.; Gain remote access to a system through a variety of means.
- Step 3 (Exploit): [Modify Windows registry] The adversary will modify the Windows registry by adding a new entry to the "run keys" referencing a desired program. This program will be run whenever the user logs in.

## Prerequisites

- The adversary must have gained access to the target system via physical or logical means in order to carry out this attack.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data, Gain Privileges

## Mitigations to bypass

- Identify programs that may be used to acquire process information and block them by using a software restriction policy or tools that restrict program execution by using a process allowlist.

## Example instances (payload / topology hints)

- An adversary can place a malicious executable (RAT) on the target system and then configure it to automatically run when the user logs in to maintain persistence on the target system.
- Through the modification of registry "run keys" the adversary can masquerade a malicious executable as a legitimate program.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-203](CAPEC-203.md)
- CanPrecede → [CAPEC-568](CAPEC-568.md)
- CanPrecede → [CAPEC-529](CAPEC-529.md)
- CanPrecede → [CAPEC-646](CAPEC-646.md)
- CanFollow → [CAPEC-555](CAPEC-555.md)

## Related CWEs (run the cwe skill)

- [CWE-15](../cwe/references/CWE-15.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-270 and CWE IDs
