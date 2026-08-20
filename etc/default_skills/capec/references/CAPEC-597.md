# CAPEC-597: Absolute Path Traversal

- Catalog: [CAPEC-597](https://capec.mitre.org/data/definitions/597.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: not stated
- CAPEC list: 3.9

## Attack pattern

An adversary with access to file system resources, either directly or via application logic, will use various file absolute paths and navigation mechanisms such as ".." to extend their range of access to inappropriate areas of the file system. The goal of the adversary is to access directories and files that are intended to be restricted from their access.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-597 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::FileFu, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-597 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-597`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Fingerprinting of the operating system] In order to perform a valid path traversal, the adversary needs to know what the underlying OS is so that the proper file seperator is used. | techniques: Port mapping. Identify ports that the system is listening on, and attempt to identify inputs and protocol types on those ports.; TCP/IP Fingerprinting. The adversary uses various softwa…
- Step 2 (Explore): [Survey application] Using manual or automated means, an adversary will survey the target application looking for all areas where user input is taken to specify a file name or path. | techniques: Use a spidering tool to follow and record all links on a web page. Make special note of any links that include parameters in the URL.; Use a proxy tool to record all links visited durin…
- Step 3 (Experiment): [Attempt variations on input parameters] Using manual or automated means, an adversary attempts varying absolute file paths on all found user input locations and observes the responses. | techniques: Access common files in root directories such as "/bin", "/boot", "/lib", or "/home"; Access a specific drive letter or windows volume letter by specifying "C:dirname" for example…
- Step 4 (Exploit): [Access, modify, or execute arbitrary files.] An adversary injects absolute path traversal syntax into identified vulnerable inputs to cause inappropriate reading, writing or execution of files. An adversary could be able to read directories or files which they are normally not allowed to read. The adversary could also access data outside the web document root, or include script…

## Prerequisites

- The target must leverage and access an underlying file system.

## Skills required

- Low: Simple command line attacks.
- Medium: Programming attacks.

## Resources required

- The attacker must have access to an application interface or a direct shell that allows them to inject directory strings and monitor the results.

## Oracles (consequences)

- Integrity, Confidentiality, Availability: Execute Unauthorized Commands — The attacker may be able to create or overwrite critical files that are used to execute code, such as programs or libraries.
- Integrity: Modify Data — The attacker may be able to overwrite or create critical files, such as programs, libraries, or important data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. For example, appending a new account at the end of a password file may allow…
- Confidentiality: Read Data — The attacker may be able read the contents of unexpected files and expose sensitive data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. For example, by reading a password file, the attacker could conduct brute force password guessing…
- Availability: Unreliable Execution — The attacker may be able to overwrite, delete, or corrupt unexpected critical files such as programs, libraries, or important data. This may prevent the software from working at all and in the case of a protection mechanisms such as authentication, it has the potential to lockout every user of the…

## Mitigations to bypass

- Design: Configure the access control correctly.
- Design: Enforce principle of least privilege.
- Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.
- Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement.
- Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.
- Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.
- Implementation: Perform input validation for all remote content, including remote and user-generated content.
- Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.
- Implementation: Use indirect references rather than actual file names.
- Implementation: Use possible permissions on file access when developing and deploying web applications.
- Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification using an allowlist approach.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-126](CAPEC-126.md)

## Related CWEs (run the cwe skill)

- [CWE-36](../cwe/references/CWE-36.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-597 and CWE IDs
