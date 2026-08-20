# CWE-23: Relative Path Traversal

- Catalog: [CWE-23](https://cwe.mitre.org/data/definitions/23.html)
- Abstraction: Base · Structure: Simple · Status: Draft
- Likelihood of exploit: not stated
- CWE list: 4.20

## Weakness

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as ".." that can resolve to a location that is outside of that directory.



## Exhaustive test law

This is a base weakness. Find every sink/source pair in scope and test each one. One vulnerable parameter is not exhaustion.

Do not mark CWE-23 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

PWN::Plugins::FileFu, PWN::Plugins::BurpSuite, PWN::SAST path modules

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-23 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-23 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-23`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: Not Language-Specific (Undetermined)
- Technology: Not Technology-Specific (Undetermined)
- Technology: Web Based (Often)
- Technology: AI/ML (Often)

## Modes of introduction

- Implementation

## Oracles (common consequences)

- Integrity, Confidentiality, Availability: Execute Unauthorized Code or Commands — The attacker may be able to create or overwrite critical files that are used to execute code, such as programs or libraries.
- Integrity: Modify Files or Directories — The attacker may be able to overwrite or create critical files, such as programs, libraries, or important data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. For example, appending a new account at the end of a password file may allow…
- Confidentiality: Read Files or Directories — The attacker may be able read the contents of unexpected files and expose sensitive data by traversing the file system to access files or directories that are outside of the restricted directory. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mec…
- Availability: DoS: Crash, Exit, or Restart — The attacker may be able to overwrite, delete, or corrupt unexpected critical files such as programs, libraries, or important data. This may prevent the product from working at all and in the case of a protection mechanisms such as authentication, it has the potential to lockout every user of the p…

## Detection methods to run

- Automated Static Analysis: Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origi…

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

The following URLs are vulnerable to this attack:

The following code could be for a social networking application in which each user's profile information is stored in a separate file. All files are stored in a single directory.

The following code demonstrates the unrestricted upload of a file with a Java servlet and a path traversal vulnerability. The action attribute of an HTML form is sending the upload file request to the Java servlet.

## Related CWEs (test these too)

- ChildOf → [CWE-22](CWE-22.md)
- ChildOf → [CWE-22](CWE-22.md)
- ChildOf → [CWE-22](CWE-22.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-23
