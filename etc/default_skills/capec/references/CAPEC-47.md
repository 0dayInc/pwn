# CAPEC-47: Buffer Overflow via Parameter Expansion

- Catalog: [CAPEC-47](https://capec.mitre.org/data/definitions/47.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

In this attack, the target software is given input that the adversary knows will be modified and expanded in size during processing. This attack relies on the target software failing to anticipate that the expanded data may exceed some internal limit, thereby creating a buffer overflow.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-47 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST BannedFunctionCallsC / UseAfterFree, PWN::Plugins::Assembly

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-47 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-47`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target application] The adversary identifies a target application or program to perform the buffer overflow on. Adversaries often look for applications that accept user input and that perform manual memory management.
- Step 2 (Experiment): [Find injection vector] The adversary identifies an injection vector to deliver the excessive content to the targeted application's buffer. | techniques: In this attack, the normal method of providing large user input does not work. The program performs bounds checking on the user input, but not the expanded user input. The adversary needs to provide input that they beli…
- Step 3 (Experiment): [Craft overflow content] The adversary crafts the input to be given to the program. If the intent is to simply cause the software to crash, the input needs only to expand to an excessive quantity of random data. If the intent is to leverage the overflow for execution of arbitrary code, the adversary will craft input that expands in a way that not only overflows the targeted b…
- Step 4 (Exploit): [Overflow the buffer] Using the injection vector, the adversary gives the crafted input to the program, overflowing the buffer.

## Prerequisites

- The program expands one of the parameters passed to a function with input controlled by the user, but a later function making use of the expanded parameter erroneously considers the original, not the expanded size of the parameter.
- The expanded parameter is used in the context where buffer overflow may become possible due to the incorrect understanding of the parameter size (i.e. thinking that it is smaller than it really is).

## Skills required

- High: Finding this particular buffer overflow may not be trivial. Also, stack and especially heap based buffer overflows require a lot of knowledge if the intended goal is arbitrary code execution. Not only that the adversary needs to write the shell code to accomplish their goals, but the adversary also…

## Resources required

- Access to the program source or binary. If the program is only available in binary then a disassembler and other reverse engineering tools will be helpful.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Availability: Unreliable Execution
- Integrity: Modify Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality: Read Data

## Mitigations to bypass

- Ensure that when parameter expansion happens in the code that the assumptions used to determine the resulting size of the parameter are accurate and that the new size of the parameter is visible to the whole system

## Example instances (payload / topology hints)

- Attack Example: FTP glob() The glob() function in FTP servers has been susceptible to attack as a result of incorrect resizing. This is an ftpd glob() Expansion LIST Heap Overflow Vulnerability. ftp daemon contains a heap-based buffer overflow condition. The overflow occurs when the LIST command is issued with an argument that expands into an oversized string after being processed by glob(). This…
- Buffer overflow in the glob implementation in libc in NetBSD-current before 20050914, and NetBSD 2.* and 3.* before 20061203, as used by the FTP daemon, allows remote authenticated users to execute arbitrary code via a long pathname that results from path expansion. The limit computation of an internal buffer was done incorrectly. The size of the buffer in byte was used as element count, even tho…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-100](CAPEC-100.md)

## Related CWEs (run the cwe skill)

- [CWE-120](../cwe/references/CWE-120.md) — run that CWE procedure after this CAPEC flow
- [CWE-119](../cwe/references/CWE-119.md) — run that CWE procedure after this CAPEC flow
- [CWE-118](../cwe/references/CWE-118.md) — run that CWE procedure after this CAPEC flow
- [CWE-130](../cwe/references/CWE-130.md) — run that CWE procedure after this CAPEC flow
- [CWE-131](../cwe/references/CWE-131.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-680](../cwe/references/CWE-680.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-47 and CWE IDs
