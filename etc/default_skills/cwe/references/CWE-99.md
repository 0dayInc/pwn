# CWE-99: Improper Control of Resource Identifiers ('Resource Injection')

- Catalog: [CWE-99](https://cwe.mitre.org/data/definitions/99.html)
- Abstraction: Class · Structure: Simple · Status: Draft
- Likelihood of exploit: High
- CWE list: 4.20

## Weakness

The product receives input from an upstream component, but it does not restrict or incorrectly restricts the input before it is used as an identifier for a resource that may be outside the intended sphere of control.

## Extended description

A resource injection issue occurs when the following two conditions are met: An attacker can specify the identifier used to access a system resource. For example, an attacker might be able to specify part of the name of a file to be opened or a port number to be used. By specifying the resource, the attacker gains a capability that would not otherwise be permitted. For example, the program may give the attacker the ability to overwrite the specified file, run with a configuration controlled by the attacker, or transmit sensitive information to a third-party server. This may enable an attacker to access or modify otherwise protected system resources.

## Exhaustive test law

This is a class. Inventory every concrete Base/Variant child that matches the target language/platform, then execute those child procedures. A class-level note is not a finding.

Do not mark CWE-99 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

skills_recall cwe → read references/CWE-<id>.md; pwn_eval for protocol probes; PWN::Plugins::BurpSuite or TransparentBrowser for HTTP; PWN::SAST::Factory.start when source exists; shell only for host tools

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-99 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-99 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-99`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: Not Language-Specific (Undetermined)

## Modes of introduction

- Architecture and Design
- Implementation — REALIZATION: This weakness is caused during implementation of an architectural security tactic.

## Oracles (common consequences)

- Confidentiality, Integrity: Read Application Data, Modify Application Data, Read Files or Directories, Modify Files or Directories — An attacker could gain access to or modify sensitive data or system resources. This could allow access to protected files or directories including configuration files and files containing sensitive information.

## Detection methods to run

- Automated Static Analysis: Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origi…

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

The following Java code uses input from an HTTP request to create a file name. The programmer has not considered the possibility that an attacker could provide a file name such as "../../tomcat/conf/server.xml", which causes the application to delete one of its own configuration files.

The following code uses input from the command line to determine which file to open and echo back to the user. If the program runs with privileges and malicious users can create soft links to the file, they can use the program to read the first part of any file on the system.

## Related CWEs (test these too)

- ChildOf → [CWE-74](CWE-74.md)
- PeerOf → [CWE-706](CWE-706.md)
- CanAlsoBe → [CWE-73](CWE-73.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-99
