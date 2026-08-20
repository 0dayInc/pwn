# CAPEC-69: Target Programs with Elevated Privileges

- Catalog: [CAPEC-69](https://capec.mitre.org/data/definitions/69.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

This attack targets programs running with elevated privileges. The adversary tries to leverage a vulnerability in the running program and get arbitrary code to execute with elevated privileges.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-69 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-69 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-69`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find programs with elevated priveleges] The adversary probes for programs running with elevated privileges. | techniques: Look for programs that write to the system directories or registry keys (such as HKLM, which stores a number of critical Windows environment variables). These programs are typically running with elevated privileges and…
- Step 2 (Explore): [Find vulnerability in running program] The adversary looks for a vulnerability in the running program that would allow for arbitrary code execution with the privilege of the running program. | techniques: Look for improper input validation; Look for improper failure safety. For instance when a program fails it may authorize restricted access to anyone.; Look for a buffer overfl…
- Step 3 (Exploit): [Execute arbitrary code] The adversary exploits the vulnerability that they have found. For instance, they can try to inject and execute arbitrary code or write to OS resources.

## Prerequisites

- The targeted program runs with elevated OS privileges.
- The targeted program accepts input data from the user or from another program.
- The targeted program is giving away information about itself. Before performing such attack, an eventual attacker may need to gather information about the services running on the host target. The more the host target is verbose about the services that are running (version number of application, etc.) the more information can be gather by an attacker.
- This attack often requires communicating with the host target services directly. For instance Telnet may be enough to communicate with the host target.

## Skills required

- Low: An attacker can use a tool to scan and automatically launch an attack against known issues. A tool can also repeat a sequence of instructions and try to brute force the service on the host target, an example of that would be the flooding technique.
- Medium: More advanced attack may require knowledge of the protocol spoken by the host service.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality, Access Control, Authorization: Gain Privileges
- Availability: Resource Consumption — Denial of Service

## Mitigations to bypass

- Apply the principle of least privilege.
- Validate all untrusted data.
- Apply the latest patches.
- Scan your services and disable the ones which are not needed and are exposed unnecessarily. Exposing programs increases the attack surface. Only expose the services which are needed and have security mechanisms such as authentication built around them.
- Avoid revealing information about your system (e.g., version of the program) to anonymous users.
- Make sure that your program or service fail safely. What happen if the communication protocol is interrupted suddenly? What happen if a parameter is missing? Does your system have resistance and resilience to attack? Fail safely when a resource exhaustion occurs.
- If possible use a sandbox model which limits the actions that programs can take. A sandbox restricts a program to a set of privileges and commands that make it difficult or impossible for the program to cause any damage.
- Check your program for buffer overflow and format String vulnerabilities which can lead to execution of malicious code.
- Monitor traffic and resource usage and pay attention if resource exhaustion occurs.
- Protect your log file from unauthorized modification and log forging.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-233](CAPEC-233.md)
- CanPrecede → [CAPEC-8](CAPEC-8.md)
- CanPrecede → [CAPEC-9](CAPEC-9.md)
- CanPrecede → [CAPEC-10](CAPEC-10.md)
- CanPrecede → [CAPEC-67](CAPEC-67.md)

## Related CWEs (run the cwe skill)

- [CWE-250](../cwe/references/CWE-250.md) — run that CWE procedure after this CAPEC flow
- [CWE-15](../cwe/references/CWE-15.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-69 and CWE IDs
