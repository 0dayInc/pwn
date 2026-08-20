# CAPEC-26: Leveraging Race Conditions

- Catalog: [CAPEC-26](https://capec.mitre.org/data/definitions/26.html)
- Abstraction: Meta · Status: Stable
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

The adversary targets a race condition occurring when multiple processes access and manipulate the same resource concurrently, and the outcome of the execution depends on the particular order in which the access takes place. The adversary can leverage a race condition by "running the race", modifying the resource and modifying the normal execution flow. For instance, a race condition can occur while accessing a file: the adversary can trick the system by replacing the original file with their version and cause the system to read the malicious file.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-26 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-26 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-26`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): The adversary explores to gauge what level of access they have.
- Step 2 (Experiment): The adversary gains access to a resource on the target host. The adversary modifies the targeted resource. The resource's value is used to determine the next normal execution action.
- Step 3 (Exploit): The resource is modified/checked concurrently by multiple processes. By using one of the processes, the adversary is able to modify the value just before it is consumed by a different process. A race condition occurs and is exploited by the adversary to abuse the target host.

## Prerequisites

- A resource is accessed/modified concurrently by multiple processes such that a race condition exists.
- The adversary has the ability to modify the resource.

## Skills required

- Medium: Being able to "run the race" requires basic knowledge of concurrent processing including synchonization techniques.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Integrity: Modify Data

## Mitigations to bypass

- Use safe libraries to access resources such as files.
- Be aware that improper use of access function calls such as chown(), tempfile(), chmod(), etc. can cause a race condition.
- Use synchronization to control the flow of execution.
- Use static analysis tools to find race conditions.
- Pay attention to concurrency problems related to the access of resources.

## Example instances (payload / topology hints)

- The Net Direct client for Linux before 6.0.5 in Nortel Application Switch 2424, VPN 3050 and 3070, and SSL VPN Module 1000 extracts and executes files with insecure permissions, which allows local users to exploit a race condition to replace a world-writable file in /tmp/NetClient and cause another user to execute arbitrary code when attempting to execute this client, as demonstrated by replacing…
- The following code illustrates a file that is accessed multiple times by name in a publicly accessible directory. A race condition exists between the accesses where an attacker can replace the file referenced by the name (see [REF-107]). include <sys/types.h> include <fcntl.h> include <unistd.h> define FILE "/tmp/myfile" define UID 100 void test(char *str) { int fd; fd = creat(FILE, 0644); if(fd…

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- [CWE-368](../cwe/references/CWE-368.md) — run that CWE procedure after this CAPEC flow
- [CWE-363](../cwe/references/CWE-363.md) — run that CWE procedure after this CAPEC flow
- [CWE-366](../cwe/references/CWE-366.md) — run that CWE procedure after this CAPEC flow
- [CWE-370](../cwe/references/CWE-370.md) — run that CWE procedure after this CAPEC flow
- [CWE-362](../cwe/references/CWE-362.md) — run that CWE procedure after this CAPEC flow
- [CWE-662](../cwe/references/CWE-662.md) — run that CWE procedure after this CAPEC flow
- [CWE-689](../cwe/references/CWE-689.md) — run that CWE procedure after this CAPEC flow
- [CWE-667](../cwe/references/CWE-667.md) — run that CWE procedure after this CAPEC flow
- [CWE-665](../cwe/references/CWE-665.md) — run that CWE procedure after this CAPEC flow
- [CWE-1223](../cwe/references/CWE-1223.md) — run that CWE procedure after this CAPEC flow
- [CWE-1254](../cwe/references/CWE-1254.md) — run that CWE procedure after this CAPEC flow
- [CWE-1298](../cwe/references/CWE-1298.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-26 and CWE IDs
