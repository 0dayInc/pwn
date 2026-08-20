# CWE-20: Improper Input Validation

- Catalog: [CWE-20](https://cwe.mitre.org/data/definitions/20.html)
- Abstraction: Class · Structure: Simple · Status: Stable
- Likelihood of exploit: High
- CWE list: 4.20

## Weakness

The product receives input or data, but it does
 not validate or incorrectly validates that the input has the
 properties that are required to process the data safely and
 correctly.

## Extended description

Input validation is a frequently-used technique
 for checking potentially dangerous inputs in order to
 ensure that the inputs are safe for processing within the
 code, or when communicating with other components. Input can consist of: raw data - strings, numbers, parameters, file contents, etc. metadata - information about the raw data, such as headers or size Data can be simple or structured. Structured data
 can be composed of many nested layers, composed of
 combinations of metadata and raw data, with other simple or
 structured data. Many properties of raw data or metadata may need
 to be validated upon entry into the code, such
 as: specified quantities such as size, length, frequency, price, rate, number of operations, time, etc. implied or derived quantities, such as the actual size of a file instead of a specified size indexes, offsets, or positions into more complex data structures symbolic keys or other elements into hash tables, associative arrays, etc. well-formedness, i.e. syntactic correctness - compliance with expected syntax lexical token correctness - compliance with rules for what is treated as a token specified or derived type - the actual type of the input (or what the input appears to be) consistency - between individual data elements, between raw data and metadata, between references, etc. conformance to domain-specific rules, e.g. business logic equivalence - ensuring that equivalent inputs are treated the same authenticity, ownership, or other attestations about the input, e.g. a cryptographic signature to prove the source of the data Implied or derived properties of data must often
 be calculated or inferred by the code itself. Errors in
 deriving properties may be considered a contributing factor
 to improper input validation.

## Exhaustive test law

This is a class. Inventory every concrete Base/Variant child that matches the target language/platform, then execute those child procedures. A class-level note is not a finding.

Do not mark CWE-20 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

skills_recall cwe → read references/CWE-<id>.md; pwn_eval for protocol probes; PWN::Plugins::BurpSuite or TransparentBrowser for HTTP; PWN::SAST::Factory.start when source exists; shell only for host tools

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-20 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-20 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-20`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: Not Language-Specific (Often)
- Technology: AI/ML (Often)

## Modes of introduction

- Architecture and Design
- Implementation — REALIZATION: This weakness is caused during implementation of an architectural security tactic. If a programmer believes that an attacker cannot modify certain inputs, then the programmer might not perform any input validation at all. For example, in web applications, many programmers believe that…

## Oracles (common consequences)

- Availability: DoS: Crash, Exit, or Restart, DoS: Resource Consumption (CPU), DoS: Resource Consumption (Memory) — An attacker could provide unexpected values and cause a program crash or arbitrary control of resource allocation, leading to excessive consumption of resources such as memory and CPU.
- Confidentiality: Read Memory, Read Files or Directories — An attacker could read confidential data if they are able to control resource references.
- Integrity, Confidentiality, Availability: Modify Memory, Execute Unauthorized Code or Commands — An attacker could use malicious input to modify data or possibly alter control flow in unexpected ways, including arbitrary command execution.

## Detection methods to run

- Automated Static Analysis: Some instances of improper input validation can be detected using automated static analysis. A static analysis tool might allow the user to specify which application-specific methods or functions perform input validation; the tool might also have built-in knowledge of validation frameworks such as Struts. The tool may then suppress or de-prioritize any associated warnin…
- Manual Static Analysis: When custom input validation is required, such as when enforcing business rules, manual analysis is necessary to ensure that the validation is properly implemented.
- Fuzzing: Fuzzing techniques can be useful for detecting input validation errors. When unexpected inputs are provided to the software, the software should not crash or otherwise become unstable, and it should generate application-controlled error messages. If exceptions or interpreter-generated error messages occur, this indicates that the input was not detected and handled within the application…
- Automated Static Analysis - Binary or Bytecode: According to SOAR [REF-1479], the following detection techniques may be useful: Cost effective for partial coverage: Bytecode Weakness Analysis - including disassembler + source code weakness analysis Binary Weakness Analysis - including disassembler + source code weakness analysis (effectiveness: SOAR Partial)
- Manual Static Analysis - Binary or Bytecode: According to SOAR [REF-1479], the following detection techniques may be useful: Cost effective for partial coverage: Binary / Bytecode disassembler - then use manual analysis for vulnerabilities & anomalies (effectiveness: SOAR Partial)
- Dynamic Analysis with Automated Results Interpretation: According to SOAR [REF-1479], the following detection techniques may be useful: Highly cost effective: Web Application Scanner Web Services Scanner Database Scanners (effectiveness: High)
- Dynamic Analysis with Manual Results Interpretation: According to SOAR [REF-1479], the following detection techniques may be useful: Highly cost effective: Fuzz Tester Framework-based Fuzzer Cost effective for partial coverage: Host Application Interface Scanner Monitored Virtual Environment - run potentially malicious code in sandbox / wrapper / virtual machine, see if it does anything suspiciou…
- Manual Static Analysis - Source Code: According to SOAR [REF-1479], the following detection techniques may be useful: Highly cost effective: Focused Manual Spotcheck - Focused manual analysis of source Manual Source Code Review (not inspections) (effectiveness: High)
- Automated Static Analysis - Source Code: According to SOAR [REF-1479], the following detection techniques may be useful: Highly cost effective: Source code Weakness Analyzer Context-configured Source Code Weakness Analyzer (effectiveness: High)
- Architecture or Design Review: According to SOAR [REF-1479], the following detection techniques may be useful: Highly cost effective: Inspection (IEEE 1028 standard) (can apply to requirements, design, source code, etc.) Formal Methods / Correct-By-Construction Cost effective for partial coverage: Attack Modeling (effectiveness: High)

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

This example demonstrates a shopping interaction in which the user is free to specify the quantity of items to be purchased and a total is calculated.

This example asks the user for a height and width of an m X n game board with a maximum dimension of 100 squares.

The following example shows a PHP application in which the programmer attempts to display a user's birthday and homepage.

## Related CWEs (test these too)

- ChildOf → [CWE-707](CWE-707.md)
- PeerOf → [CWE-345](CWE-345.md)
- CanPrecede → [CWE-22](CWE-22.md)
- CanPrecede → [CWE-41](CWE-41.md)
- CanPrecede → [CWE-74](CWE-74.md)
- CanPrecede → [CWE-119](CWE-119.md)
- CanPrecede → [CWE-770](CWE-770.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-20
