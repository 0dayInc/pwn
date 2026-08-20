# CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)

- Catalog: [CWE-80](https://cwe.mitre.org/data/definitions/80.html)
- Abstraction: Variant · Structure: Simple · Status: Incomplete
- Likelihood of exploit: High
- CWE list: 4.20

## Weakness

The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special characters such as "<", ">", and "&" that could be interpreted as web-scripting elements when they are sent to a downstream component that processes web pages.



## Exhaustive test law

This is a variant. Run the parent Base tests, then the variant-specific oracles below. Do not skip the parent.

Do not mark CWE-80 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser, PWN::Plugins::Zaproxy, PWN::SAST innerHTML/postMessage modules

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-80 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-80 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-80`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: Not Language-Specific (Undetermined)
- Technology: Web Based (Often)
- Technology: Web Server (Undetermined)

## Modes of introduction

- Implementation

## Oracles (common consequences)

- Confidentiality, Integrity, Availability: Read Application Data, Execute Unauthorized Code or Commands — An attacker could insert special characters that are processed client-side in the context of the user's session.

## Detection methods to run

- Automated Static Analysis: Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origi…

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

In the following example, a guestbook comment isn't properly encoded, filtered, or otherwise neutralized for script-related tags before being displayed in a client browser.

## Related CWEs (test these too)

- ChildOf → [CWE-79](CWE-79.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-80
