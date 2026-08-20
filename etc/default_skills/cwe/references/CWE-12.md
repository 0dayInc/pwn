# CWE-12: ASP.NET Misconfiguration: Missing Custom Error Page

- Catalog: [CWE-12](https://cwe.mitre.org/data/definitions/12.html)
- Abstraction: Variant · Structure: Simple · Status: Draft
- Likelihood of exploit: not stated
- CWE list: 4.20

## Weakness

An ASP .NET application must enable custom error pages in order to prevent attackers from mining information from the framework's built-in responses.



## Exhaustive test law

This is a variant. Run the parent Base tests, then the variant-specific oracles below. Do not skip the parent.

Do not mark CWE-12 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

skills_recall cwe → read references/CWE-<id>.md; pwn_eval for protocol probes; PWN::Plugins::BurpSuite or TransparentBrowser for HTTP; PWN::SAST::Factory.start when source exists; shell only for host tools

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-12 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-12 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-12`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: ASP.NET (Undetermined)

## Modes of introduction

- Implementation
- Operation

## Oracles (common consequences)

- Confidentiality: Read Application Data — Default error pages gives detailed information about the error that occurred, and should not be used in production environments. Attackers can leverage the additional information provided by a default error page to mount attacks targeted on the framework, database, or other resources used by the ap…

## Detection methods to run

- (none listed in CWE catalog)

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

The mode attribute of the <customErrors> tag in the Web.config file defines whether custom or default error pages are used.

## Related CWEs (test these too)

- ChildOf → [CWE-756](CWE-756.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-12
