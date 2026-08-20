# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

- Catalog: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
- Abstraction: Base · Structure: Simple · Status: Stable
- Likelihood of exploit: High
- CWE list: 4.20

## Weakness

The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component. Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.



## Exhaustive test law

This is a base weakness. Find every sink/source pair in scope and test each one. One vulnerable parameter is not exhaustion.

Do not mark CWE-89 complete because a scanner listed it. Complete means every in-scope instance was attacked or ruled out with saved evidence.

## Tooling (PWN)

PWN::SAST SQL modules, PWN::Plugins::BurpSuite, PWN::Plugins::Fuzz, PWN::Plugins::DAOPostgres / DAOSQLite3 for sink confirmation

## Procedure

1. **Applicability gate.** Read platforms and introduction phases. If the target has none of them, record a dated negative (`CWE-89 N/A: <reason>`) and stop. Otherwise continue.
2. **Instance inventory.** List every occurrence: routes, parameters, APIs, functions, files, hardware pins, parsers. Use SAST hits, proxy sitemap, `dump_links`, symbols, or firmware strings. Inventory is incomplete if you only sampled the homepage or one binary function.
3. **Oracle definition.** From Common Consequences, write a pass/fail check per instance (unauthorized data out, unexpected control flow, crash, auth bypass, etc.).
4. **Attack each instance.** Use Demonstrative Examples as the minimum payload set, then mutate: encoding, method, verb, content-type, length, type juggling, second-order, authenticated vs anonymous. Do not claim coverage from a single benign request.
5. **Instrument.** Capture request/response or stdin/stdout, debugger backtrace, or serial log. Persist under `/tmp` or the engagement report dir. Read the artifact back (`write_verified?` analog: a later read of the saved evidence).
6. **Mitigation negation.** For each Potential Mitigation, attempt the attack with the control present and absent (or bypassed). A mitigation that does not change the oracle is not a control.
7. **Adjacent CWEs.** Run the related IDs below (parents first, then peers). Stopping at CWE-89 while a ChildOf parent is also present is incomplete.
8. **Report.** Every finding cites `CWE-89`, instance, oracle, evidence path, and residual risk. A narrative without an artifact is not a test.

## Applicable platforms

- Language: Not Language-Specific (Undetermined)
- Language: SQL (Often)
- Technology: Database Server (Undetermined)

## Modes of introduction

- Implementation — REALIZATION: This weakness is caused during implementation of an architectural security tactic.
- Implementation — This weakness typically appears in data-rich applications that save user inputs in a database.

## Oracles (common consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Code or Commands — Adversaries could execute system commands, typically by changing the SQL statement to redirect output to a file that can then be executed.
- Confidentiality: Read Application Data — Since SQL databases generally hold sensitive data, loss of confidentiality is a frequent problem with SQL injection vulnerabilities.
- Authentication: Gain Privileges or Assume Identity, Bypass Protection Mechanism — If poor SQL commands are used to check user names and passwords or perform other kinds of authentication, it may be possible to connect to the product as another user with no previous knowledge of the password.
- Access Control: Bypass Protection Mechanism — If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.
- Integrity: Modify Application Data — Just as it may be possible to read sensitive information, it is also possible to modify or even delete this information with a SQL injection attack.

## Detection methods to run

- Automated Static Analysis: This weakness can often be detected using automated static analysis tools. Many modern tools use data flow analysis or constraint-based techniques to minimize the number of false positives. Automated static analysis might not be able to recognize when proper input validation is being performed, leading to false positives - i.e., warnings that do not have any security co…
- Automated Dynamic Analysis: This weakness can be detected using dynamic tools and techniques that interact with the software using large test suites with many diverse inputs, such as fuzz testing (fuzzing), robustness testing, and fault injection. The software's operation may slow down, but it should not become unstable, crash, or generate incorrect results. (effectiveness: Moderate)
- Manual Analysis: Manual analysis can be useful for finding this weakness, but it might not achieve desired code coverage within limited time constraints. This becomes difficult for weaknesses that must be considered for all inputs, since the attack surface can be too large.
- Automated Static Analysis - Binary or Bytecode: According to SOAR [REF-1479], the following detection techniques may be useful: Highly cost effective: Bytecode Weakness Analysis - including disassembler + source code weakness analysis Binary Weakness Analysis - including disassembler + source code weakness analysis (effectiveness: High)
- Dynamic Analysis with Automated Results Interpretation: According to SOAR [REF-1479], the following detection techniques may be useful: Highly cost effective: Database Scanners Cost effective for partial coverage: Web Application Scanner Web Services Scanner (effectiveness: High)
- Dynamic Analysis with Manual Results Interpretation: According to SOAR [REF-1479], the following detection techniques may be useful: Cost effective for partial coverage: Fuzz Tester Framework-based Fuzzer (effectiveness: SOAR Partial)
- Manual Static Analysis - Source Code: According to SOAR [REF-1479], the following detection techniques may be useful: Highly cost effective: Manual Source Code Review (not inspections) Cost effective for partial coverage: Focused Manual Spotcheck - Focused manual analysis of source (effectiveness: High)
- Automated Static Analysis - Source Code: According to SOAR [REF-1479], the following detection techniques may be useful: Highly cost effective: Source code Weakness Analyzer Context-configured Source Code Weakness Analyzer (effectiveness: High)
- Architecture or Design Review: According to SOAR [REF-1479], the following detection techniques may be useful: Highly cost effective: Formal Methods / Correct-By-Construction Cost effective for partial coverage: Inspection (IEEE 1028 standard) (can apply to requirements, design, source code, etc.) (effectiveness: High)

## Mitigations to attempt to bypass

- (none listed in CWE catalog)

## Demonstrative examples (minimum payload hints)

In 2008, a large number of web servers were compromised using the same SQL injection attack string. This single string worked against many different programs. The SQL injection was then used to modify the web sites to serve malicious code.

The following code dynamically constructs and executes a SQL query that searches for items matching a specified name. The query restricts the items displayed to those where owner matches the user name of the currently-authenticated user.

This example examines the effects of a different malicious value passed to the query constructed and executed in the previous example.

## Related CWEs (test these too)

- ChildOf → [CWE-943](CWE-943.md)
- ChildOf → [CWE-74](CWE-74.md)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory exists and is more than one guess
- [ ] Each instance has an oracle result
- [ ] Evidence artifact path is saved and was re-read
- [ ] Related parent/peer CWEs handled or explicitly deferred
- [ ] Finding (if any) cites CWE-89
