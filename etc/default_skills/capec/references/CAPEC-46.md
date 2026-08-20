# CAPEC-46: Overflow Variables and Tags

- Catalog: [CAPEC-46](https://capec.mitre.org/data/definitions/46.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This type of attack leverages the use of tags or variables from a formatted configuration data to cause buffer overflow. The adversary crafts a malicious HTML page or configuration file that includes oversized strings, thus causing an overflow.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-46 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST BannedFunctionCallsC / UseAfterFree, PWN::Plugins::Assembly

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-46 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-46`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target application] The adversary identifies a target application or program to perform the buffer overflow on. Adversaries look for applications or programs that accept formatted files, such as configuration files, as input.
- Step 2 (Experiment): [Find injection vector] The adversary identifies an injection vector to deliver the excessive content to the targeted application's buffer. | techniques: Knowing the type of file that an application takes as input, the adversary takes a normal input file and modifies a single variable or tag to contain a large amount of data. If there is a crash, this means that a buffer…
- Step 3 (Experiment): [Craft overflow content] The adversary crafts the content to be injected. If the intent is to simply cause the software to crash, the content need only consist of an excessive quantity of random data. If the intent is to leverage the overflow for execution of arbitrary code, the adversary crafts the payload in such a way that the overwritten return address is replaced with on…
- Step 4 (Exploit): [Overflow the buffer] The adversary will upload the crafted file to the application, causing a buffer overflow.

## Prerequisites

- The target program consumes user-controllable data in the form of tags or variables.
- The target program does not perform sufficient boundary checking.

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
- Use an abstraction library to abstract away risky APIs. Not a complete solution.
- Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.
- Use OS-level preventative functionality. Not a complete solution.
- Do not trust input data from user. Validate all user input.

## Example instances (payload / topology hints)

- A buffer overflow vulnerability exists in the Yamaha MidiPlug that can be accessed via a Text variable found in an EMBED tag. See also: CVE-1999-0946
- A buffer overflow in Exim allows local users to gain root privileges by providing a long :include: option in a .forward file. See also: CVE-1999-0971

## Related CAPECs (test these too)

- ChildOf → [CAPEC-100](CAPEC-100.md)
- PeerOf → [CAPEC-8](CAPEC-8.md)
- PeerOf → [CAPEC-10](CAPEC-10.md)

## Related CWEs (run the cwe skill)

- [CWE-120](../cwe/references/CWE-120.md) — run that CWE procedure after this CAPEC flow
- [CWE-118](../cwe/references/CWE-118.md) — run that CWE procedure after this CAPEC flow
- [CWE-119](../cwe/references/CWE-119.md) — run that CWE procedure after this CAPEC flow
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
- [ ] Finding (if any) cites CAPEC-46 and CWE IDs
