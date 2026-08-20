# CAPEC-29: Leveraging Time-of-Check and Time-of-Use (TOCTOU) Race Conditions

- Catalog: [CAPEC-29](https://capec.mitre.org/data/definitions/29.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack targets a race condition occurring between the time of check (state) for a resource and the time of use of a resource. A typical example is file access. The adversary can leverage a file access race condition by "running the race", meaning that they would modify the resource between the first time the target program accesses the file and the time the target program uses the file. During that period of time, the adversary could replace or modify the file, causing the application to behave unexpectedly.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-29 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-29 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-29`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): The adversary explores to gauge what level of access they have.
- Step 2 (Experiment): The adversary confirms access to a resource on the target host. The adversary confirms ability to modify the targeted resource.
- Step 3 (Exploit): The adversary decides to leverage the race condition by "running the race", meaning that they would modify the resource between the first time the target program accesses the file and the time the target program uses the file. During that period of time, the adversary can replace the resource and cause an escalation of privilege.

## Prerequisites

- A resource is access/modified concurrently by multiple processes.
- The adversary is able to modify resource.
- A race condition exists while accessing a resource.

## Skills required

- Medium: This attack can get sophisticated since the attack has to occur within a short interval of time.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Integrity, Availability: Alter Execution Logic
- Confidentiality: Read Data
- Availability: Resource Consumption — Denial of Service

## Mitigations to bypass

- Use safe libraries to access resources such as files.
- Be aware that improper use of access function calls such as chown(), tempfile(), chmod(), etc. can cause a race condition.
- Use synchronization to control the flow of execution.
- Use static analysis tools to find race conditions.
- Pay attention to concurrency problems related to the access of resources.

## Example instances (payload / topology hints)

- The Net Direct client for Linux before 6.0.5 in Nortel Application Switch 2424, VPN 3050 and 3070, and SSL VPN Module 1000 extracts and executes files with insecure permissions, which allows local users to exploit a race condition to replace a world-writable file in /tmp/NetClient and cause another user to execute arbitrary code when attempting to execute this client, as demonstrated by replacing…
- The following code illustrates a file that is accessed multiple times by name in a publicly accessible directory. A race condition exists between the accesses where an adversary can replace the file referenced by the name. include <sys/types.h> include <fcntl.h> include <unistd.h> define FILE "/tmp/myfile" define UID 100 void test(char *str) { int fd; fd = creat(FILE, 0644); if(fd == -1) return;…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-26](CAPEC-26.md)

## Related CWEs (run the cwe skill)

- [CWE-367](../cwe/references/CWE-367.md) — run that CWE procedure after this CAPEC flow
- [CWE-368](../cwe/references/CWE-368.md) — run that CWE procedure after this CAPEC flow
- [CWE-366](../cwe/references/CWE-366.md) — run that CWE procedure after this CAPEC flow
- [CWE-370](../cwe/references/CWE-370.md) — run that CWE procedure after this CAPEC flow
- [CWE-362](../cwe/references/CWE-362.md) — run that CWE procedure after this CAPEC flow
- [CWE-662](../cwe/references/CWE-662.md) — run that CWE procedure after this CAPEC flow
- [CWE-691](../cwe/references/CWE-691.md) — run that CWE procedure after this CAPEC flow
- [CWE-663](../cwe/references/CWE-663.md) — run that CWE procedure after this CAPEC flow
- [CWE-665](../cwe/references/CWE-665.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-29 and CWE IDs
