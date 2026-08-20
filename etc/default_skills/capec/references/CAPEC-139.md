# CAPEC-139: Relative Path Traversal

- Catalog: [CAPEC-139](https://capec.mitre.org/data/definitions/139.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker exploits a weakness in input validation on the target by supplying a specially constructed path utilizing dot and slash characters for the purpose of obtaining access to arbitrary files or resources. An attacker modifies a known path on the target in order to reach material that is not available through intended channels. These attacks normally involve adding additional path separators (/ or \) and/or dots (.), or encodings thereof, in various combinations in order to reach parent directories or entirely separate trees of the target's directory structure.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-139 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::FileFu, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-139 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-139`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Fingerprinting of the operating system] In order to perform a valid path traversal, the adversary needs to know what the underlying OS is so that the proper file seperator is used. | techniques: Port mapping. Identify ports that the system is listening on, and attempt to identify inputs and protocol types on those ports.; TCP/IP Fingerprinting. The adversary uses various softwa…
- Step 2 (Explore): [Survey application] Using manual or automated means, an adversary will survey the target application looking for all areas where user input is taken to specify a file name or path. | techniques: Use a spidering tool to follow and record all links on a web page. Make special note of any links that include parameters in the URL.; Use a proxy tool to record all links visited durin…
- Step 3 (Experiment): [Attempt variations on input parameters] Using manual or automated means, an adversary attempts varying relative file path combinations on all found user input locations and observes the responses. | techniques: Provide "../" or "..\" at the beginning of any filename to traverse to the parent directory; Use a list of probe strings as path traversal payload. Different strings…
- Step 4 (Exploit): [Access, modify, or execute arbitrary files.] An adversary injects path traversal syntax into identified vulnerable inputs to cause inappropriate reading, writing or execution of files. An adversary could be able to read directories or files which they are normally not allowed to read. The adversary could also access data outside the web document root, or include scripts, source…

## Prerequisites

- The target application must accept a string as user input, fail to sanitize combinations of characters in the input that have a special meaning in the context of path navigation, and insert the user-supplied string into path navigation commands.

## Skills required

- Low: To inject the malicious payload in a web page
- High: To bypass non trivial filters in the application

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Access Control: Bypass Protection Mechanism
- Availability: Unreliable Execution

## Mitigations to bypass

- Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement
- Implementation: Perform input validation for all remote content, including remote and user-generated content.
- Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- using an allowlist approach.
- Implementation: Prefer working without user input when using file system calls
- Implementation: Use indirect references rather than actual file names.
- Implementation: Use possible permissions on file access when developing and deploying web applications.

## Example instances (payload / topology hints)

- The attacker uses relative path traversal to access files in the application. This is an example of accessing user's password file. http://www.example.com/getProfile.jsp?filename=../../../../etc/passwd However, the target application employs regular expressions to make sure no relative path sequences are being passed through the application to the web page. The application would replace all match…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-126](CAPEC-126.md)

## Related CWEs (run the cwe skill)

- [CWE-23](../cwe/references/CWE-23.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-139 and CWE IDs
