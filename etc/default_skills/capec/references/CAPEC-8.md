# CAPEC-8: Buffer Overflow in an API Call

- Catalog: [CAPEC-8](https://capec.mitre.org/data/definitions/8.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack targets libraries or shared code modules which are vulnerable to buffer overflow attacks. An adversary who has knowledge of known vulnerable libraries or shared code can easily target software that makes use of these libraries. All clients that make use of the code library thus become vulnerable by association. This has a very broad effect on security across a system, usually affecting more than one software process.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-8 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST BannedFunctionCallsC / UseAfterFree, PWN::Plugins::Assembly

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-8 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-8`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target application] The adversary, with knowledge of vulnerable libraries or shared code modules, identifies a target application or program that makes use of these.
- Step 2 (Experiment): [Find injection vector] The adversary attempts to use the API, and if they can they send a large amount of data to see if the buffer overflow attack really does work. | techniques: Provide large input to a program or application and observe the behavior. If there is a crash, this means that a buffer overflow attack is possible.
- Step 3 (Experiment): [Craft overflow content] The adversary crafts the content to be injected based on their knowledge of the vulnerability and their desired outcome. If the intent is to simply cause the software to crash, the content need only consist of an excessive quantity of random data. If the intent is to leverage the overflow for execution of arbitrary code, the adversary will craft a set…
- Step 4 (Exploit): [Overflow the buffer] Using the API as the injection vector, the adversary injects the crafted overflow content into the buffer.

## Prerequisites

- The target host exposes an API to the user.
- One or more API functions exposed by the target host has a buffer overflow vulnerability.

## Skills required

- Low: An adversary can simply overflow a buffer by inserting a long string into an adversary-modifiable injection vector. The result can be a DoS.
- High: Exploiting a buffer overflow to inject malicious code into the stack of a software system or even the heap can require a higher skill level.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Availability: Unreliable Execution
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Use a language or compiler that performs automatic bounds checking.
- Use secure functions not vulnerable to buffer overflow.
- If you have to use dangerous functions, make sure that you do boundary checking.
- Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.
- Use OS-level preventative functionality. Not a complete solution.

## Example instances (payload / topology hints)

- Attack Example: Libc in FreeBSD A buffer overflow in the FreeBSD utility setlocale (found in the libc module) puts many programs at risk all at once.
- Xtlib A buffer overflow in the Xt library of the X windowing system allows local users to execute commands with root privileges.

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
- [ ] Finding (if any) cites CAPEC-8 and CWE IDs
