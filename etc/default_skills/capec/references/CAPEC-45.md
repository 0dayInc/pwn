# CAPEC-45: Buffer Overflow via Symbolic Links

- Catalog: [CAPEC-45](https://capec.mitre.org/data/definitions/45.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This type of attack leverages the use of symbolic links to cause buffer overflows. An adversary can try to create or manipulate a symbolic link file such that its contents result in out of bounds data. When the target software processes the symbolic link file, it could potentially overflow internal buffers with insufficient bounds checking.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-45 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST BannedFunctionCallsC / UseAfterFree, PWN::Plugins::Assembly

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-45 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-45`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target application] The adversary identifies a target application or program that might load in certain files to memory.
- Step 2 (Experiment): [Find injection vector] The adversary identifies an injection vector to deliver the excessive content to the targeted application's buffer. | techniques: The adversary creates or modifies a symbolic link pointing to those files which contain an excessive amount of data. If creating a symbolic link to one of those files causes different behavior in the application, then a…
- Step 3 (Experiment): [Craft overflow file content] The adversary crafts the content to be injected. If the intent is to simply cause the software to crash, the content need only consist of an excessive quantity of random data. If the intent is to leverage the overflow for execution of arbitrary code, the adversary crafts the payload in such a way that the overwritten return address is replaced wi…
- Step 4 (Exploit): [Overflow the buffer] Using the specially crafted file content, the adversary creates a symbolic link from the identified resource to the malicious file, causing a targeted buffer overflow attack.

## Prerequisites

- The adversary can create symbolic link on the target host.
- The target host does not perform correct boundary checking while consuming data from a resources.

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

- Pay attention to the fact that the resource you read from can be a replaced by a Symbolic link. You can do a Symlink check before reading the file and decide that this is not a legitimate way of accessing the resource.
- Because Symlink can be modified by an adversary, make sure that the ones you read are located in protected directories.
- Pay attention to the resource pointed to by your symlink links (See attack pattern named "Forced Symlink race"), they can be replaced by malicious resources.
- Always check the size of the input data before copying to a buffer.
- Use a language or compiler that performs automatic bounds checking.
- Use an abstraction library to abstract away risky APIs. Not a complete solution.
- Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.
- Use OS-level preventative functionality. Not a complete solution.

## Example instances (payload / topology hints)

- The EFTP server has a buffer overflow that can be exploited if an adversary uploads a .lnk (link) file that contains more than 1,744 bytes. This is a classic example of an indirect buffer overflow. First the adversary uploads some content (the link file) and then the adversary causes the client consuming the data to be exploited. In this example, the ls command is exploited to compromise the serv…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-100](CAPEC-100.md)

## Related CWEs (run the cwe skill)

- [CWE-120](../cwe/references/CWE-120.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-302](../cwe/references/CWE-302.md) — run that CWE procedure after this CAPEC flow
- [CWE-118](../cwe/references/CWE-118.md) — run that CWE procedure after this CAPEC flow
- [CWE-119](../cwe/references/CWE-119.md) — run that CWE procedure after this CAPEC flow
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
- [ ] Finding (if any) cites CAPEC-45 and CWE IDs
