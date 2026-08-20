# CAPEC-696: Load Value Injection

- Catalog: [CAPEC-696](https://capec.mitre.org/data/definitions/696.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits a hardware design flaw in a CPU implementation of transient instruction execution in which a faulting or assisted load instruction transiently forwards adversary-controlled data from microarchitectural buffers. By inducing a page fault or microcode assist during victim execution, an adversary can force legitimate victim execution to operate on the adversary-controlled data which is stored in the microarchitectural buffers. The adversary can then use existing code gadgets and side channel analysis to discover victim secrets that have not yet been flushed from microarchitectural state or hijack the system control flow.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-696 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-696 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-696`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey target application and relevant OS shared code libraries] Adversary identifies vulnerable transient instruction sets and the code/function calls to trigger them as well as instruction sets or code fragments (gadgets) to perform attack. The adversary looks for code gadgets which will allow them to load an adversary-controlled value into trusted memory. They also look for…
- Step 2 (Experiment): [Fill microarchitectural buffer with controlled value] The adversary will utilize the found code gadget from the previous step to load a value into a microarchitectural buffer. | techniques: The adversary may choose the controlled value to be memory address of sensitive information that they want the system to access; The adversary may choose the controlled value to be the me…
- Step 3 (Experiment): [Set up instruction to page fault or microcode assist] The adversary must manipulate the system such that a page fault or microcode assist occurs when a valid instruction is run. If the instruction that fails is near where the adversary-controlled value was loaded, the system may forward this value from the microarchitectural buffer incorrectly. | techniques: When targeting I…
- Step 4 (Exploit): [Operate on adversary-controlled data] Once the attack has been set up and the page fault or microcode assist occurs, the system operates on the adversary-controlled data. | techniques: Influence the system to load sensitive information into microarchitectural state which can be read by the adversary using a code gadget.; Hijack execution by jumping to second stage gadgets found…

## Prerequisites

- The adversary needs at least user execution access to a system and a maliciously crafted program/application/process with unprivileged code to misuse transient instruction set execution of the CPU.
- The CPU incorrectly transiently forwards values from microarchitectural buffers after faulting or assisted loads
- The adversary needs the ability to induce page faults or microcode assists on the target system.
- Code gadgets exist that allow the adversary to hijack transient execution and encode secrets into the microarchitectural state.

## Skills required

- High: Detailed knowledge on how various CPU architectures and microcode perform transient execution for various low-level assembly language code instructions/operations.
- High: Detailed knowledge on compiled binaries and operating system shared libraries of instruction sequences, and layout of application and OS/Kernel address spaces for data leakage.
- High: The ability to provoke faulting or assisted loads in legitimate execution.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality: Read Data
- Access Control: Bypass Protection Mechanism
- Authorization: Execute Unauthorized Commands

## Mitigations to bypass

- Do not allow the forwarding of data resulting from a faulting or assisted instruction. Some current mitigations claim to zero out the forwarded data, but this mitigation still does not suffice.
- Insert explicit “lfence” speculation barriers in software before potentially faulting or assisted loads. This halts transient execution until all previous instructions have been executed and ensures that the architecturally correct value is forwarded.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-663](CAPEC-663.md)

## Related CWEs (run the cwe skill)

- [CWE-1342](../cwe/references/CWE-1342.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-696 and CWE IDs
