# CAPEC-663: Exploitation of Transient Instruction Execution

- Catalog: [CAPEC-663](https://capec.mitre.org/data/definitions/663.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: Low · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits a hardware design flaw in a CPU implementation of transient instruction execution to expose sensitive data and bypass/subvert access control over restricted resources. Typically, the adversary conducts a covert channel attack to target non-discarded microarchitectural changes caused by transient executions such as speculative execution, branch prediction, instruction pipelining, and/or out-of-order execution. The transient execution results in a series of instructions (gadgets) which construct covert channel and access/transfer the secret data.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-663 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-663 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-663`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey target application and relevant OS shared code libraries] Adversary identifies vulnerable transient instruction sets and the code/function calls to trigger them as well as instruction sets or code fragments (gadgets) to perform attack. | techniques: Utilize Disassembler and Debugger tools to examine and trace instruction set execution of source code and shared code libra…
- Step 2 (Explore): [Explore cache and identify impacts] Utilize tools to understand the impact of transient instruction execution upon address spaces and CPU operations. | techniques: Run OS or application specific tools that examine the contents of cache.
- Step 1 (Experiment): [Cause conditions for identified transient instruction set execution] Adversary ensures that specific code/instructions of the target process are executed by CPU, so desired transient instructions are executed.
- Step 2 (Experiment): [Cause specific secret data to be cached from restricted address space] Executed instruction sets (gadgets) in target address space, initially executed via adversary-chosen transient instructions sets, establish covert channel and transfer secret data across this channel to cache. | techniques: Prediction-based - adversary trains CPU to incorrectly predict/speculate condition…
- Step 1 (Exploit): [Perform covert channel attack to obtain/access secret data] Adversary process code removes instructions/data from shared cache set, waits for target process to reinsert them back into cache, to identify location of secret data via a timing method. Adversary continuously repeat this process to identify and access entirety of targeted secret data. | techniques: Flush+Reload - adv…

## Prerequisites

- The adversary needs at least user execution access to a system and a maliciously crafted program/application/process with unprivileged code to misuse transient instruction set execution of the CPU.

## Skills required

- High: Detailed knowledge on how various CPU architectures and microcode perform transient execution for various low-level assembly language code instructions/operations.
- High: Detailed knowledge on compiled binaries and operating system shared libraries of instruction sequences, and layout of application and OS/Kernel address spaces for data leakage.

## Resources required

- C2C mechanism or direct access to victim system, capable of dropping malicious program and collecting covert channel attack data.
- Malicious program capable of triggering execution of transient instructions or vulnerable instruction sequences of victim program and performing a covert channel attack to gather data from victim process memory space. Ultimately, the speed with which an attacker discovers a secret is directly proportional to the computational resources of the victim machine.

## Oracles (consequences)

- Confidentiality: Read Data
- Access Control: Bypass Protection Mechanism
- Authorization: Execute Unauthorized Commands

## Mitigations to bypass

- Implementation: DAWG (Dynamically Allocated Way Guard) - processor cache properly divided between different programs/processes that don't share resources
- Implementation: KPTI (Kernel Page-Table Isolation) to completely separate user-space and kernel space page tables
- Configuration: Architectural Design of Microcode to limit abuse of speculative execution and out-of-order execution
- Configuration: Disable SharedArrayBuffer for Web Browsers
- Configuration: Disable Copy-on-Write between Cloud VMs
- Configuration: Privilege Checks on Cache Flush Instructions
- Implementation: Non-inclusive Cache Memories to prevent Flush+Reload Attacks

## Example instances (payload / topology hints)

- A web browser with user-privileges executes JavaScript code imbedded within a malicious website. The system does not disable shared buffers for the web browser and there is no restriction or check upon user-process execution of flush or evict instructions. The Javascript code executes vulnerable transient instructions upon system to cause microarchitectural changes that establish covert channel a…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-74](CAPEC-74.md)
- ChildOf → [CAPEC-184](CAPEC-184.md)
- CanPrecede → [CAPEC-141](CAPEC-141.md)
- PeerOf → [CAPEC-212](CAPEC-212.md)
- PeerOf → [CAPEC-124](CAPEC-124.md)
- PeerOf → [CAPEC-180](CAPEC-180.md)

## Related CWEs (run the cwe skill)

- [CWE-1037](../cwe/references/CWE-1037.md) — run that CWE procedure after this CAPEC flow
- [CWE-1303](../cwe/references/CWE-1303.md) — run that CWE procedure after this CAPEC flow
- [CWE-1264](../cwe/references/CWE-1264.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-663 and CWE IDs
