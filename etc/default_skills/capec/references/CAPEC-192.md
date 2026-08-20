# CAPEC-192: Protocol Analysis

- Catalog: [CAPEC-192](https://capec.mitre.org/data/definitions/192.html)
- Abstraction: Meta · Status: Stable
- Likelihood of attack: Low · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

An adversary engages in activities to decipher and/or decode protocol information for a network or application communication protocol used for transmitting information between interconnected nodes or systems on a packet-switched data network. While this type of analysis involves the analysis of a networking protocol inherently, it does not require the presence of an actual or physical network.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-192 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-192 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-192`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- Access to a binary executable.
- The ability to observe and interact with a communication channel between communicating processes.

## Skills required

- High: Knowlegde of the Open Systems Interconnection model (OSI model), and famililarity with Wireshark or some other packet analyzer.

## Resources required

- Depending on the type of analysis, a variety of tools might be required, such as static code and/or dynamic analysis tools. Alternatively, the effort might require debugging programs such as ollydbg, SoftICE, or disassemblers like IDA Pro. In some instances, packet sniffing or packet analyzing programs such as TCP dump or Wireshark are necessary. Lastly, specific protocol analysis might require t…

## Oracles (consequences)

- Confidentiality: Read Data — Successful deciphering of protocol information compromises the confidentiality of future sensitive communications.
- Integrity: Modify Data — Modifying communications after successful deciphering of protocol information compromises integrity.

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- [CWE-326](../cwe/references/CWE-326.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-192 and CWE IDs
