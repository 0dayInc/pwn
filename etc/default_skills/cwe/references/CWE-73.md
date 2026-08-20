# CWE-73: External Control of File Name or Path

- Catalog: [CWE-73](https://cwe.mitre.org/data/definitions/73.html)
- Abstraction: Base · Structure: Simple · Status: Draft
- Likelihood of exploit: High
- CWE list: 4.20

## Weakness

The product allows user input to control or influence paths or file names that are used in filesystem operations.

## Extended description

This could allow an attacker to access or modify system files or other files that are critical to the application. Path manipulation errors occur when the following two conditions are met: 1. An attacker can specify a path used in an operation on the filesystem. 2. By specifying the resource, the attacker gains a capability that would not otherwise be permitted. For example, the program may give the attacker the ability to overwrite the specified file or run with a configuration controlled by the attacker.

## Exhaustive test law

This is a base weakness. Find every sink/source pair in scope and test each one. One vulnerable parameter is not exhaustion.

Do not mark CWE-73 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

skills_recall cwe → read references/CWE-<id>.md; pwn_eval for protocol probes; PWN::Plugins::BurpSuite or TransparentBrowser for HTTP; PWN::SAST::Factory.start when source exists; shell only for host tools

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-73 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-73 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-73`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: Not Language-Specific (Undetermined)
- Operating_System: Unix (Often)
- Operating_System: Windows (Often)
- Operating_System: macOS (Often)

## Modes of introduction

- Architecture and Design
- Implementation — REALIZATION: This weakness is caused during implementation of an architectural security tactic.

## Oracles (common consequences)

- Integrity, Confidentiality: Read Files or Directories, Modify Files or Directories — The application can operate on unexpected files. Confidentiality is violated when the targeted filename is not directly readable by the attacker.
- Integrity, Confidentiality, Availability: Modify Files or Directories, Execute Unauthorized Code or Commands — The application can operate on unexpected files. This may violate integrity if the filename is written to, or if the filename is for a program or other form of executable code.
- Availability: DoS: Crash, Exit, or Restart, DoS: Resource Consumption (Other) — The application can operate on unexpected files. Availability can be violated if the attacker specifies an unexpected file that the application modifies. Availability can also be affected if the attacker specifies a filename for a large file, or points to a special device or a file that does not ha…

## Detection methods to run

- Automated Static Analysis: The external control or influence of filenames can often be detected using automated static analysis that models data flow within the product. Automated static analysis might not be able to recognize when proper input validation is being performed, leading to false positives - i.e., warnings that do not have any security consequences or require any code changes.

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

The following code uses input from an HTTP request to create a file name. The programmer has not considered the possibility that an attacker could provide a file name such as "../../tomcat/conf/server.xml", which causes the application to delete one of its own configuration files (CWE-22).

The following code uses input from a configuration file to determine which file to open and echo back to the user. If the program runs with privileges and malicious users can change the configuration file, they can use the program to read any file on the system that ends with the extension .txt.

## Related CWEs (test these too)

- ChildOf → [CWE-642](CWE-642.md)
- ChildOf → [CWE-610](CWE-610.md)
- ChildOf → [CWE-20](CWE-20.md)
- CanPrecede → [CWE-22](CWE-22.md)
- CanPrecede → [CWE-41](CWE-41.md)
- CanPrecede → [CWE-98](CWE-98.md)
- CanPrecede → [CWE-434](CWE-434.md)
- CanPrecede → [CWE-59](CWE-59.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-73
