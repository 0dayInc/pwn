# CAPEC-237: Escaping a Sandbox by Calling Code in Another Language

- Catalog: [CAPEC-237](https://capec.mitre.org/data/definitions/237.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

The attacker may submit malicious code of another language to obtain access to privileges that were not intentionally exposed by the sandbox, thus escaping the sandbox. For instance, Java code cannot perform unsafe operations, such as modifying arbitrary memory locations, due to restrictions placed on it by the Byte code Verifier and the JVM. If allowed, Java code can call directly into native C code, which may perform unsafe operations, such as call system calls and modify arbitrary memory locations on their behalf. To provide isolation, Java does not grant untrusted code with unmediated access to native C code. Instead, the sandboxed code is typically allowed to call some subset of the pre-existing native code that is part of standard libraries.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-237 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-237 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-237`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Probing] The attacker probes the target application to see whether calling code of another language is allowed within a sandbox. | techniques: The attacker probes the target application to see whether calling code of another language is allowed within a sandbox.
- Step 2 (Explore): [Analysis] The attacker analyzes the target application to get a list of cross code weaknesses in the standard libraries of the sandbox. | techniques: The attacker analyzes the target application to get a list of cross code weaknesses in the standard libraries of the sandbox.
- Step 3 (Experiment): [Verify the exploitable security weaknesses] The attacker tries to craft malicious code of another language allowed by the sandbox to verify the security weaknesses of the standard libraries found in the Explore phase. | techniques: The attacker tries to explore the security weaknesses by calling malicious code of another language allowed by the sandbox.
- Step 4 (Exploit): [Exploit the security weaknesses in the standard libraries] The attacker calls malicious code of another language to exploit the security weaknesses in the standard libraries verified in the Experiment phase. The attacker will be able to obtain access to privileges that were not intentionally exposed by the sandbox, thus escaping the sandbox. | techniques: The attacker calls mal…

## Prerequisites

- (none listed in CAPEC catalog)

## Skills required

- High: The attacker must have a good knowledge of the platform specific mechanisms of signing and verifying code. Most code signing and verification schemes are based on use of cryptography, the attacker needs to have an understand of these cryptographic operations in good detail.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Access Control, Authorization: Bypass Protection Mechanism
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges

## Mitigations to bypass

- Assurance: Sanitize the code of the standard libraries to make sure there is no security weaknesses in them.
- Design: Use obfuscation and other techniques to prevent reverse engineering the standard libraries.
- Assurance: Use static analysis tool to do code review and dynamic tool to do penetration test on the standard library.
- Configuration: Get latest updates for the computer.

## Example instances (payload / topology hints)

- Exploit: Java/ByteVerify.C is a detection of malicious code that attempts to exploit a vulnerability in the Microsoft Virtual Machine (VM). The VM enables Java programs to run on Windows platforms. The Microsoft Java VM is included in most versions of Windows and Internet Explorer. In some versions of the Microsoft VM, a vulnerability exists because of a flaw in the way the ByteCode Verifier chec…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-480](CAPEC-480.md)

## Related CWEs (run the cwe skill)

- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-237 and CWE IDs
