# CWE-96: Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')

- Catalog: [CWE-96](https://cwe.mitre.org/data/definitions/96.html)
- Abstraction: Base · Structure: Simple · Status: Draft
- Likelihood of exploit: not stated
- CWE list: 4.20

## Weakness

The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before inserting the input into an executable resource, such as a library, configuration file, or template.



## Exhaustive test law

This is a base weakness. Find every sink/source pair in scope and test each one. One vulnerable parameter is not exhaustion.

Do not mark CWE-96 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

skills_recall cwe → read references/CWE-<id>.md; pwn_eval for protocol probes; PWN::Plugins::BurpSuite or TransparentBrowser for HTTP; PWN::SAST::Factory.start when source exists; shell only for host tools

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-96 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-96 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-96`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: PHP (Undetermined)
- Language: Perl (Undetermined)
- Language: Interpreted (Undetermined)

## Modes of introduction

- Implementation — REALIZATION: This weakness is caused during implementation of an architectural security tactic.
- Implementation — This issue is frequently found in PHP applications that allow users to set configuration variables that are stored within executable PHP files. Technically, this could also be performed in some compiled code (e.g., by byte-patching an executable), although it is highly unlikely.

## Oracles (common consequences)

- Confidentiality: Read Files or Directories, Read Application Data — The injected code could access restricted data / files.
- Access Control: Bypass Protection Mechanism — In some cases, injectable code controls authentication; this may lead to a remote vulnerability.
- Access Control: Gain Privileges or Assume Identity — Injected code can access resources that the attacker is directly prevented from accessing.
- Integrity, Confidentiality, Availability, Other: Execute Unauthorized Code or Commands — Code injection attacks can lead to loss of data integrity in nearly all cases as the control-plane data injected is always incidental to data recall or writing. Additionally, code injection can often result in the execution of arbitrary code.
- Non-Repudiation: Hide Activities — Often the actions performed by injected control code are unlogged.

## Detection methods to run

- Automated Static Analysis: Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origi…

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

This example attempts to write user messages to a message file and allow users to view them.

## Related CWEs (test these too)

- ChildOf → [CWE-94](CWE-94.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-96
