# CAPEC-30: Hijacking a Privileged Thread of Execution

- Catalog: [CAPEC-30](https://capec.mitre.org/data/definitions/30.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Low · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary hijacks a privileged thread of execution by injecting malicious code into a running process. By using a privleged thread to do their bidding, adversaries can evade process-based detection that would stop an attack that creates a new process. This can lead to an adversary gaining access to the process's memory and can also enable elevated privileges. The most common way to perform this attack is by suspending an existing thread and manipulating its memory.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-30 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-30 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-30`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine target thread] The adversary determines the underlying system thread that is subject to user-control
- Step 2 (Experiment): [Gain handle to thread] The adversary then gains a handle to a process thread. | techniques: Use the "OpenThread" API call in Windows on a known thread.; Cause an exception in a java privileged block public function and catch it, or catch a normal signal. The thread is then hanging and the adversary can attempt to gain a handle to it.
- Step 3 (Experiment): [Alter process memory] Once the adversary has a handle to the target thread, they will suspend the thread and alter the memory using native OS calls. | techniques: On Windows, use "SuspendThread" followed by "VirtualAllocEx", "WriteProcessMemory", and "SetThreadContext".
- Step 4 (Exploit): [Resume thread execution] Once the process memory has been altered to execute malicious code, the thread is then resumed. | techniques: On Windows, use "ResumeThread".

## Prerequisites

- The application in question employs a threaded model of execution with the threads operating at, or having the ability to switch to, a higher privilege level than normal users
- In order to feasibly execute this class of attacks, the adversary must have the ability to hijack a privileged thread. This ability includes, but is not limited to, modifying environment variables that affect the process the thread belongs to, or calling native OS calls that can suspend and alter process memory. This does not preclude network-based attacks, but makes them conceptually more diffic…

## Skills required

- High: Hijacking a thread involves knowledge of how processes and threads function on the target platform, the design of the target application as well as the ability to identify the primitives to be used or manipulated to hijack the thread.

## Resources required

- None: No specialized resources are required to execute this type of attack. The adversary needs to be able to latch onto a privileged thread. The adversary does, however, need to be able to program, compile, and link to the victim binaries being executed so that it will turn control of a privileged thread over to the adversary's malicious code. This is the case even if the adversary conducts the…

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.
- Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

## Example instances (payload / topology hints)

- Adversary targets an application written using Java's AWT, with the 1.2.2 era event model. In this circumstance, any AWTEvent originating in the underlying OS (such as a mouse click) would return a privileged thread (e.g., a system call). The adversary could choose to not return the AWT-generated thread upon consuming the event, but instead leveraging its privilege to conduct privileged operation…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-233](CAPEC-233.md)

## Related CWEs (run the cwe skill)

- [CWE-270](../cwe/references/CWE-270.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-30 and CWE IDs
