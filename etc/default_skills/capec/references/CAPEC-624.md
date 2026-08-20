# CAPEC-624: Hardware Fault Injection

- Catalog: [CAPEC-624](https://capec.mitre.org/data/definitions/624.html)
- Abstraction: Meta · Status: Stable
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

The adversary uses disruptive signals or events, or alters the physical environment a device operates in, to cause faulty behavior in electronic devices. This can include electromagnetic pulses, laser pulses, clock glitches, ambient temperature extremes, and more. When performed in a controlled manner on devices performing cryptographic operations, this faulty behavior can be exploited to derive secret key information.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-624 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-624 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-624`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- Physical access to the system
- The adversary must be cognizant of where fault injection vulnerabilities exist in the system in order to leverage them for exploitation.

## Skills required

- High: Adversaries require non-trivial technical skills to create and implement fault injection attacks. Although this style of attack has become easier (commercial equipment and training classes are available to perform these attacks), they usual require significant setup and experimentation time during…

## Resources required

- The relevant sensors and tools to detect and analyze fault/side-channel data from a system. A tool capable of injecting fault/side-channel data into a system or application.

## Oracles (consequences)

- Confidentiality: Read Data, Bypass Protection Mechanism, Hide Activities — An adversary capable of successfully collecting and analyzing sensitive, fault/side-channel information, has compromised the confidentiality of that application or information system data.
- Integrity: Execute Unauthorized Commands — If an adversary is able to inject data via a fault or side channel vulnerability towards malicious ends, the integrity of the application or information system will be compromised.

## Mitigations to bypass

- Implement robust physical security countermeasures and monitoring.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- [CWE-1247](../cwe/references/CWE-1247.md) — run that CWE procedure after this CAPEC flow
- [CWE-1248](../cwe/references/CWE-1248.md) — run that CWE procedure after this CAPEC flow
- [CWE-1256](../cwe/references/CWE-1256.md) — run that CWE procedure after this CAPEC flow
- [CWE-1319](../cwe/references/CWE-1319.md) — run that CWE procedure after this CAPEC flow
- [CWE-1332](../cwe/references/CWE-1332.md) — run that CWE procedure after this CAPEC flow
- [CWE-1334](../cwe/references/CWE-1334.md) — run that CWE procedure after this CAPEC flow
- [CWE-1338](../cwe/references/CWE-1338.md) — run that CWE procedure after this CAPEC flow
- [CWE-1351](../cwe/references/CWE-1351.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-624 and CWE IDs
