# CAPEC-84: XQuery Injection

- Catalog: [CAPEC-84](https://capec.mitre.org/data/definitions/84.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

This attack utilizes XQuery to probe and attack server systems; in a similar manner that SQL Injection allows an attacker to exploit SQL calls to RDBMS, XQuery Injection uses improperly validated data that is passed to XQuery commands to traverse and execute commands that the XQuery routines have access to. XQuery injection can be used to enumerate elements on the victim's environment, inject commands to the local host, or execute queries to remote files and data sources.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-84 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST SQL modules, PWN::Plugins::BurpSuite, PWN::Plugins::Fuzz

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-84 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-84`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for user-controllable inputs] Using a browser or an automated tool, an attacker follows all public links and actions on a web site. They record all the links, the forms, the resources accessed and all other potential entry-points for the web application. | techniques: Use a spidering tool to follow and record all links and analyze the web pages to find en…
- Step 2 (Experiment): [Determine user-controllable input susceptible to injection] Determine the user-controllable input susceptible to injection. For each user-controllable input that the attacker suspects is vulnerable to XQL injection, attempt to inject characters that have special meaning in XQL. The goal is to create an XQL query with an invalid syntax. | techniques: Use web browser to inject…
- Step 3 (Exploit): [Information Disclosure] The attacker crafts and injects an XQuery payload which is acted on by an XQL query leading to inappropriate disclosure of information. | techniques: Leveraging one of the vulnerable inputs identified during the Experiment phase, inject malicious XQuery payload. The payload aims to get information on the structure of the underlying XML database and/or th…
- Step 4 (Exploit): [Manipulate the data in the XML database] The attacker crafts and injects an XQuery payload which is acted on by an XQL query leading to modification of application data. | techniques: Leveraging one of the vulnerable inputs identified during the Experiment phase, inject malicious XQuery payload.. The payload tries to insert or replace data in the XML database.

## Prerequisites

- The XQL must execute unvalidated data

## Skills required

- Low: Basic understanding of XQuery

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Design: Perform input allowlist validation on all XML input
- Implementation: Run xml parsing and query infrastructure with minimal privileges so that an attacker is limited in their ability to probe other system resources from XQL.

## Example instances (payload / topology hints)

- An attacker can pass XQuery expressions embedded in otherwise standard XML documents. Like SQL injection attacks, the attacker tunnels through the application entry point to target the resource access layer. The string below is an example of an attacker accessing the accounts.xml to request the service provider send all user names back. doc(accounts.xml)//user[Name='*'] The attacks that are possi…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-250](CAPEC-250.md)

## Related CWEs (run the cwe skill)

- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-707](../cwe/references/CWE-707.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-84 and CWE IDs
