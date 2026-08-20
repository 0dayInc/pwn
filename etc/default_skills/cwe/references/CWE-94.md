# CWE-94: Improper Control of Generation of Code ('Code Injection')

- Catalog: [CWE-94](https://cwe.mitre.org/data/definitions/94.html)
- Abstraction: Base · Structure: Simple · Status: Draft
- Likelihood of exploit: Medium
- CWE list: 4.20

## Weakness

The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.



## Exhaustive test law

This is a base weakness. Find every sink/source pair in scope and test each one. One vulnerable parameter is not exhaustion.

Do not mark CWE-94 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

skills_recall cwe → read references/CWE-<id>.md; pwn_eval for protocol probes; PWN::Plugins::BurpSuite or TransparentBrowser for HTTP; PWN::SAST::Factory.start when source exists; shell only for host tools

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-94 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-94 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-94`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: Interpreted (Sometimes)
- Technology: AI/ML (Undetermined)

## Modes of introduction

- Implementation — REALIZATION: This weakness is caused during implementation of an architectural security tactic.

## Oracles (common consequences)

- Access Control: Bypass Protection Mechanism — In some cases, injectable code controls authentication; this may lead to a remote vulnerability.
- Access Control: Gain Privileges or Assume Identity — Injected code can access resources that the attacker is directly prevented from accessing.
- Integrity, Confidentiality, Availability: Execute Unauthorized Code or Commands — When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product. As a result, code injection can often result in the execution of arbitrary code. Code injection attacks can…
- Non-Repudiation: Hide Activities — Often the actions performed by injected control code are unlogged.

## Detection methods to run

- Automated Static Analysis: Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origi…

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

This example attempts to write user messages to a message file and allow users to view them.

edit-config.pl: This CGI script is used to modify settings in a configuration file.

This simple python3 script asks a user to supply a comma-separated list of numbers as input and adds them together.

## Related CWEs (test these too)

- ChildOf → [CWE-74](CWE-74.md)
- ChildOf → [CWE-74](CWE-74.md)
- ChildOf → [CWE-913](CWE-913.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-94
