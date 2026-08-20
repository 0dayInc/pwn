# CAPEC-24: Filter Failure through Buffer Overflow

- Catalog: [CAPEC-24](https://capec.mitre.org/data/definitions/24.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

In this attack, the idea is to cause an active filter to fail by causing an oversized transaction. An attacker may try to feed overly long input strings to the program in an attempt to overwhelm the filter (by causing a buffer overflow) and hoping that the filter does not fail securely (i.e. the user input is let into the system unfiltered).

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-24 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST BannedFunctionCallsC / UseAfterFree, PWN::Plugins::Assembly

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-24 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-24`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey] The attacker surveys the target application, possibly as a valid and authenticated user | techniques: Spidering web sites for inputs that involve potential filtering; Brute force guessing of filtered inputs
- Step 2 (Experiment): [Attempt injections] Try to feed overly long data to the system. This can be done manually or a dynamic tool (black box) can be used to automate this. An attacker can also use a custom script for that purpose. | techniques: Brute force attack through black box penetration test tool.; Fuzzing of communications protocols; Manual testing of possible inputs with attack data.
- Step 3 (Experiment): [Monitor responses] Watch for any indication of failure occurring. Carefully watch to see what happened when filter failure occurred. Did the data get in? | techniques: Boron tagging. Choose clear attack inputs that are easy to notice in output. In binary this is often 0xa5a5a5a5 (alternating 1s and 0s). Another obvious tag value is all zeroes, but it is not always obvious wh…
- Step 4 (Exploit): [Abuse the system through filter failure] An attacker writes a script to consistently induce the filter failure. | techniques: DoS through filter failure. The attacker causes the system to crash or stay down because of its failure to filter properly.; Malicious code execution. An attacker introduces a malicious payload and executes arbitrary code on the target system.; An attack…

## Prerequisites

- Ability to control the length of data passed to an active filter.

## Skills required

- Low: An attacker can simply overflow a buffer by inserting a long string into an attacker-modifiable injection vector. The result can be a DoS.
- High: Exploiting a buffer overflow to inject malicious code into the stack of a software system or even the heap can require a higher skill level.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality, Access Control, Authorization: Bypass Protection Mechanism
- Availability: Unreliable Execution

## Mitigations to bypass

- Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.
- Pre-design: Use a language or compiler that performs automatic bounds checking.
- Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.
- Operational: Use OS-level preventative functionality. Not a complete solution.
- Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

## Example instances (payload / topology hints)

- Sending in arguments that are too long to cause the filter to fail open is one instantiation of the filter failure attack. The Taylor UUCP daemon is designed to remove hostile arguments before they can be executed. If the arguments are too long, however, the daemon fails to remove them. This leaves the door open for attack.
- A filter is used by a web application to filter out characters that may allow the input to jump from the data plane to the control plane when data is used in a SQL statement (chaining this attack with the SQL injection attack). Leveraging a buffer overflow the attacker makes the filter fail insecurely and the tainted data is permitted to enter unfiltered into the system, subsequently causing a SQ…
- Audit Truncation and Filters with Buffer Overflow. Sometimes very large transactions can be used to destroy a log file or cause partial logging failures. In this kind of attack, log processing code might be examining a transaction in real-time processing, but the oversized transaction causes a logic branch or an exception of some kind that is trapped. In other words, the transaction is still exec…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-100](CAPEC-100.md)

## Related CWEs (run the cwe skill)

- [CWE-120](../cwe/references/CWE-120.md) — run that CWE procedure after this CAPEC flow
- [CWE-119](../cwe/references/CWE-119.md) — run that CWE procedure after this CAPEC flow
- [CWE-118](../cwe/references/CWE-118.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-680](../cwe/references/CWE-680.md) — run that CWE procedure after this CAPEC flow
- [CWE-733](../cwe/references/CWE-733.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-24 and CWE IDs
