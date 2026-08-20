# CAPEC-110: SQL Injection through SOAP Parameter Tampering

- Catalog: [CAPEC-110](https://capec.mitre.org/data/definitions/110.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An attacker modifies the parameters of the SOAP message that is sent from the service consumer to the service provider to initiate a SQL injection attack. On the service provider side, the SOAP message is parsed and parameters are not properly validated before being used to access a database in a way that does not use parameter binding, thus enabling the attacker to control the structure of the executed SQL query. This pattern describes a SQL injection attack with the delivery mechanism being a SOAP message.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-110 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST SQL modules, PWN::Plugins::BurpSuite, PWN::Plugins::Fuzz

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-110 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-110`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Detect Incorrect SOAP Parameter Handling] The attacker tampers with the SOAP message parameters and looks for indications that the tampering caused a change in behavior of the targeted application. | techniques: The attacker tampers with the SOAP message parameters by injecting some special characters such as single quotes, double quotes, semi columns, etc. The attacker observe…
- Step 2 (Experiment): [Probe for SQL Injection vulnerability] The attacker injects SQL syntax into vulnerable SOAP parameters identified during the Explore phase to search for unfiltered execution of the SQL syntax in a query.
- Step 3 (Exploit): [Inject SQL via SOAP Parameters] The attacker injects SQL via SOAP parameters identified as vulnerable during Explore phase to launch a first or second order SQL injection attack. | techniques: An attacker performs a SQL injection attack via the usual methods leveraging SOAP parameters as the injection vector. An attacker has to be careful not to break the XML parser at the serv…

## Prerequisites

- SOAP messages are used as a communication mechanism in the system
- SOAP parameters are not properly validated at the service provider
- The service provider does not properly utilize parameter binding when building SQL queries

## Skills required

- Medium: If the attacker is able to gain good understanding of the system's database schema
- High: If the attacker has to perform Blind SQL Injection

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Integrity: Modify Data
- Availability: Unreliable Execution
- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Properly validate and sanitize/reject user input at the service provider.
- Ensure that prepared statements or other mechanism that enables parameter binding is used when accessing the database in a way that would prevent the attackers' supplied data from controlling the structure of the executed query.
- At the database level, ensure that the database user used by the application in a particular context has the minimum needed privileges to the database that are needed to perform the operation. When possible, run queries against pre-generated views rather than the tables directly.

## Example instances (payload / topology hints)

- An attacker uses a travel booking system that leverages SOAP communication between the client and the travel booking service. An attacker begins to tamper with the outgoing SOAP messages by modifying their parameters to include characters that would break a dynamically constructed SQL query. They notice that the system fails to respond when these malicious inputs are injected in certain parameter…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-66](CAPEC-66.md)
- CanPrecede → [CAPEC-108](CAPEC-108.md)

## Related CWEs (run the cwe skill)

- [CWE-89](../cwe/references/CWE-89.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-110 and CWE IDs
