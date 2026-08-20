# CWE-61: UNIX Symbolic Link (Symlink) Following

- Catalog: [CWE-61](https://cwe.mitre.org/data/definitions/61.html)
- Abstraction: Compound · Structure: Composite · Status: Incomplete
- Likelihood of exploit: High
- CWE list: 4.20

## Weakness

The product, when opening a file or directory, does not sufficiently account for when the file is a symbolic link that resolves to a target outside of the intended control sphere. This could allow an attacker to cause the product to operate on unauthorized files.

## Extended description

A product that allows UNIX symbolic links (symlink) as part of paths whether in internal code or through user input can allow an attacker to spoof the symbolic link and traverse the file system to unintended locations or access arbitrary files. The symbolic link can permit an attacker to read/write/corrupt a file that they originally did not have permissions to access.

## Exhaustive test law

This is a compound weakness. Build a chained PoC that requires every component; a single-bug demo is incomplete.

Do not mark CWE-61 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay (two-role replay), PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-61 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-61 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-61`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: Not Language-Specific (Undetermined)

## Modes of introduction

- Implementation — These are typically reported for temporary files or privileged programs.

## Oracles (common consequences)

- Confidentiality, Integrity: Read Files or Directories, Modify Files or Directories

## Detection methods to run

- Automated Static Analysis: Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origi…

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

- Catalog has no demonstrative example. Derive payloads from the description and related CWEs.

## Related CWEs (test these too)

- ChildOf → [CWE-59](CWE-59.md)
- Requires → [CWE-362](CWE-362.md)
- Requires → [CWE-340](CWE-340.md)
- Requires → [CWE-386](CWE-386.md)
- Requires → [CWE-732](CWE-732.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-61
