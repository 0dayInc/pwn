# CWE-8: J2EE Misconfiguration: Entity Bean Declared Remote

- Catalog: [CWE-8](https://cwe.mitre.org/data/definitions/8.html)
- Abstraction: Variant · Structure: Simple · Status: Incomplete
- Likelihood of exploit: not stated
- CWE list: 4.20

## Weakness

When an application exposes a remote interface for an entity bean, it might also expose methods that get or set the bean's data. These methods could be leveraged to read sensitive information, or to change data in ways that violate the application's expectations, potentially leading to other vulnerabilities.



## Exhaustive test law

This is a variant. Run the parent Base tests, then the variant-specific oracles below. Do not skip the parent.

Do not mark CWE-8 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

PWN::SAST Token/Password/PrivateKey/HTTPAuthorizationHeader, PWN::Plugins::Git

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-8 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-8 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-8`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: Java (Undetermined)

## Modes of introduction

- Architecture and Design
- Implementation

## Oracles (common consequences)

- Confidentiality, Integrity: Read Application Data, Modify Application Data

## Detection methods to run

- (none listed in CWE catalog)

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

The following example demonstrates the weakness.

## Related CWEs (test these too)

- ChildOf → [CWE-668](CWE-668.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-8
