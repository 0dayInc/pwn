# CAPEC-88: OS Command Injection

- Catalog: [CAPEC-88](https://capec.mitre.org/data/definitions/88.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

In this type of an attack, an adversary injects operating system commands into existing application functions. An application that uses untrusted input to build command strings is vulnerable. An adversary can leverage OS command injection in an application to elevate privileges, execute arbitrary commands and compromise the underlying operating system.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-88 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST command-exec modules, PWN::Plugins::PS

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-88 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-88`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify inputs for OS commands] The attacker determines user controllable input that gets passed as part of a command to the underlying operating system. | techniques: Port mapping. Identify ports that the system is listening on, and attempt to identify inputs and protocol types on those ports.; TCP/IP Fingerprinting. The attacker uses various software to make connections or p…
- Step 2 (Explore): [Survey the Application] The attacker surveys the target application, possibly as a valid and authenticated user | techniques: Spidering web sites for all available links; Inventory all application inputs
- Step 3 (Experiment): [Vary inputs, looking for malicious results.] Depending on whether the application being exploited is a remote or local one the attacker crafts the appropriate malicious input, containing OS commands, to be passed to the application | techniques: Inject command delimiters using network packet injection tools (netcat, nemesis, etc.); Inject command delimiters using web test fr…
- Step 4 (Exploit): [Execute malicious commands] The attacker may steal information, install a back door access mechanism, elevate privileges or compromise the system in some other way. | techniques: The attacker executes a command that stores sensitive information into a location where they can retrieve it later (perhaps using a different command injection).

## Prerequisites

- User controllable input used as part of commands to the underlying operating system.

## Skills required

- High: The attacker needs to have knowledge of not only the application to exploit but also the exact nature of commands that pertain to the target operating system. This may involve, though not always, knowledge of specific assembly commands for the platform.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality, Access Control, Authorization: Gain Privileges, Bypass Protection Mechanism
- Confidentiality: Read Data

## Mitigations to bypass

- Use language APIs rather than relying on passing data to the operating system shell or command line. Doing so ensures that the available protection mechanisms in the language are intact and applicable.
- Filter all incoming data to escape or remove characters or strings that can be potentially misinterpreted as operating system or shell commands
- All application processes should be run with the minimal privileges required. Also, processes must shed privileges as soon as they no longer require them.

## Example instances (payload / topology hints)

- A transaction processing system relies on code written in a number of languages. To access this functionality, the system passes transaction information on the system command line. An attacker can gain access to the system command line and execute malicious commands by injecting these commands in the transaction data. If successful, the attacker can steal information, install backdoors and perfor…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-248](CAPEC-248.md)

## Related CWEs (run the cwe skill)

- [CWE-78](../cwe/references/CWE-78.md) — run that CWE procedure after this CAPEC flow
- [CWE-88](../cwe/references/CWE-88.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-88 and CWE IDs
