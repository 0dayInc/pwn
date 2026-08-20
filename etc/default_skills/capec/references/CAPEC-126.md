# CAPEC-126: Path Traversal

- Catalog: [CAPEC-126](https://capec.mitre.org/data/definitions/126.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary uses path manipulation methods to exploit insufficient input validation of a target to obtain access to data that should be not be retrievable by ordinary well-formed requests. A typical variety of this attack involves specifying a path to a desired file together with dot-dot-slash characters, resulting in the file access API or function traversing out of the intended directory structure and into the root file system. By replacing or modifying the expected path information the access function or API retrieves the file desired by the attacker. These attacks either involve the attacker providing a complete path to a targeted file or using control characters (e.g. path separators (/ or \) and/or dots (.)) to reach desired directories or files.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-126 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::FileFu, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-126 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-126`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Fingerprinting of the operating system] In order to perform a valid path traversal, the attacker needs to know what the underlying OS is so that the proper file seperator is used. | techniques: Port mapping. Identify ports that the system is listening on, and attempt to identify inputs and protocol types on those ports.; TCP/IP Fingerprinting. The attacker uses various software…
- Step 2 (Explore): [Survey the Application to Identify User-controllable Inputs] The attacker surveys the target application to identify all user-controllable file inputs
- Step 3 (Experiment): [Vary inputs, looking for malicious results] Depending on whether the application being exploited is a remote or local one, the attacker crafts the appropriate malicious input containing the path of the targeted file or other file system control syntax to be passed to the application
- Step 4 (Exploit): [Manipulate files accessible by the application] The attacker may steal information or directly manipulate files (delete, copy, flush, etc.)

## Prerequisites

- The attacker must be able to control the path that is requested of the target.
- The target must fail to adequately sanitize incoming paths

## Skills required

- Low: Simple command line attacks or to inject the malicious payload in a web page.
- Medium: Customizing attacks to bypass non trivial filters in the application.

## Resources required

- The ability to manually manipulate path information either directly through a client application relative to the service or application or via a proxy application.

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
- Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- using an allowlist approach.

## Example instances (payload / topology hints)

- An example of using path traversal to attack some set of resources on a web server is to use a standard HTTP request http://example/../../../../../etc/passwd From an attacker point of view, this may be sufficient to gain access to the password file on a poorly protected system. If the attacker can list directories of critical resources then read only access is not sufficient to protect the system.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-153](CAPEC-153.md)
- CanPrecede → [CAPEC-664](CAPEC-664.md)

## Related CWEs (run the cwe skill)

- [CWE-22](../cwe/references/CWE-22.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-126 and CWE IDs
