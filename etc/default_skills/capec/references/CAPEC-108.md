# CAPEC-108: Command Line Execution through SQL Injection

- Catalog: [CAPEC-108](https://capec.mitre.org/data/definitions/108.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An attacker uses standard SQL injection methods to inject data into the command line for execution. This could be done directly through misuse of directives such as MSSQL_xp_cmdshell or indirectly through injection of data into the database that would be interpreted as shell commands. Sometime later, an unscrupulous backend application (or could be part of the functionality of the same application) fetches the injected data stored in the database and uses this data as command line arguments without performing proper validation. The malicious data escapes that data plane by spawning new commands to be executed on the host.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-108 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST SQL modules, PWN::Plugins::BurpSuite, PWN::Plugins::Fuzz

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-108 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-108`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Probe for SQL Injection vulnerability] The attacker injects SQL syntax into user-controllable data inputs to search unfiltered execution of the SQL syntax in a query.
- Step 2 (Exploit): [Achieve arbitrary command execution through SQL Injection with the MSSQL_xp_cmdshell directive] The attacker leverages a SQL Injection attack to inject shell code to be executed by leveraging the xp_cmdshell directive.
- Step 3 (Exploit): [Inject malicious data in the database] Leverage SQL injection to inject data in the database that could later be used to achieve command injection if ever used as a command line argument
- Step 4 (Exploit): [Trigger command line execution with injected arguments] The attacker causes execution of command line functionality which leverages previously injected database content as arguments.

## Prerequisites

- The application does not properly validate data before storing in the database
- Backend application implicitly trusts the data stored in the database
- Malicious data is used on the backend as a command line argument

## Skills required

- High: The attacker most likely has to be familiar with the internal functionality of the system to launch this attack. Without that knowledge, there are not many feedback mechanisms to give an attacker the indication of how to perform command injection or whether the attack is succeeding.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Availability: Unreliable Execution
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Disable MSSQL xp_cmdshell directive on the database
- Properly validate the data (syntactically and semantically) before writing it to the database.
- Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

## Example instances (payload / topology hints)

- SQL injection vulnerability in Cacti 0.8.6i and earlier, when register_argc_argv is enabled, allows remote attackers to execute arbitrary SQL commands via the (1) second or (2) third arguments to cmd.php. NOTE: this issue can be leveraged to execute arbitrary commands since the SQL query results are later used in the polling_items array and popen function (CVE-2006-6799). Reference: https://www.c…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-66](CAPEC-66.md)

## Related CWEs (run the cwe skill)

- [CWE-89](../cwe/references/CWE-89.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-78](../cwe/references/CWE-78.md) — run that CWE procedure after this CAPEC flow
- [CWE-114](../cwe/references/CWE-114.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-108 and CWE IDs
