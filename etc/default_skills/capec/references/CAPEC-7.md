# CAPEC-7: Blind SQL Injection

- Catalog: [CAPEC-7](https://capec.mitre.org/data/definitions/7.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

Blind SQL Injection results from an insufficient mitigation for SQL Injection. Although suppressing database error messages are considered best practice, the suppression alone is not sufficient to prevent SQL Injection. Blind SQL Injection is a form of SQL Injection that overcomes the lack of error messages. Without the error messages that facilitate SQL Injection, the adversary constructs input strings that probe the target through simple Boolean SQL expressions. The adversary can determine if the syntax and structure of the injection was successful based on whether the query was executed or not. Applied iteratively, the adversary determines how and where the target is vulnerable to SQL Injection.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-7 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST SQL modules, PWN::Plugins::BurpSuite, PWN::Plugins::Fuzz

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-7 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-7`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Hypothesize SQL queries in application] Generated hypotheses regarding the SQL queries in an application. For example, the adversary may hypothesize that their input is passed directly into a query that looks like: "SELECT * FROM orders WHERE ordernum = _____" or "SELECT * FROM orders WHERE ordernum IN (_____)" or "SELECT * FROM orders WHERE ordernum in (_____) ORDER BY _____"…
- Step 2 (Explore): [Determine how to inject information into the queries] Determine how to inject information into the queries from the previous step such that the injection does not impact their logic. For example, the following are possible injections for those queries: "5' OR 1=1; --" and "5) OR 1=1; --" and "ordernum DESC; --" | techniques: Add clauses to the SQL queries such that the query lo…
- Step 3 (Experiment): [Determine user-controllable input susceptible to injection] Determine the user-controllable input susceptible to injection. For each user-controllable input that the adversary suspects is vulnerable to SQL injection, attempt to inject the values determined in the previous step. If an error does not occur, then the adversary knows that the SQL injection was successful. | tech…
- Step 4 (Experiment): [Determine database type] Determines the type of the database, such as MS SQL Server or Oracle or MySQL, using logical conditions as part of the injected queries | techniques: Try injecting a string containing char(0x31)=char(0x31) (this evaluates to 1=1 in SQL Server only); Try injecting a string containing 0x313D31 (this evaluates to 1=1 in MySQL only); Inject other databas…
- Step 5 (Exploit): [Extract information about database schema] Extract information about database schema by getting the database to answer yes/no questions about the schema. | techniques: Automatically extract database schema using a tool such as Absinthe.; Manually perform the blind SQL Injection to extract desired information about the database schema.
- Step 6 (Exploit): [Exploit SQL Injection vulnerability] Use the information obtained in the previous steps to successfully inject the database in order to bypass checks or modify, add, retrieve or delete data from the database | techniques: Use information about how to inject commands into SQL queries as well as information about the database schema to execute attacks such as dropping tables, ins…

## Prerequisites

- SQL queries used by the application to store, retrieve or modify data.
- User-controllable input that is not properly validated by the application as part of SQL queries.

## Skills required

- Medium: Determining the database type and version, as well as the right number and type of parameters to the query being injected in the absence of error messages requires greater skill than reverse-engineering database error messages.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Security by Obscurity is not a solution to preventing SQL Injection. Rather than suppress error messages and exceptions, the application must handle them gracefully, returning either a custom error page or redirecting the user to a default page, without revealing any information about the database or the application internals.
- Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as SQL content. Keywords such as UNION, SELECT or INSERT must be filtered in addition to characters such as a single-quote(') or SQL-comments (--) based on the context in which they appear.

## Example instances (payload / topology hints)

- An adversary may try entering something like "username' AND 1=1; --" in an input field. If the result is the same as when the adversary entered "username" in the field, then the adversary knows that the application is vulnerable to SQL Injection. The adversary can then ask yes/no questions from the database server to extract information from it. For example, the adversary can extract table names…
- In the PHP application TimeSheet 1.1, an adversary can successfully retrieve username and password hashes from the database using Blind SQL Injection. If the adversary is aware of the local path structure, the adversary can also remotely execute arbitrary code and write the output of the injected queries to the local path. Blind SQL Injection is possible since the application does not properly sa…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-66](CAPEC-66.md)

## Related CWEs (run the cwe skill)

- [CWE-89](../cwe/references/CWE-89.md) — run that CWE procedure after this CAPEC flow
- [CWE-209](../cwe/references/CWE-209.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow
- [CWE-707](../cwe/references/CWE-707.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-7 and CWE IDs
