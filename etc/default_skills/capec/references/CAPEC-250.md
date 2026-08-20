# CAPEC-250: XML Injection

- Catalog: [CAPEC-250](https://capec.mitre.org/data/definitions/250.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: not stated
- CAPEC list: 3.9

## Attack pattern

An attacker utilizes crafted XML user-controllable input to probe, attack, and inject data into the XML database, using techniques similar to SQL injection. The user-controllable input can allow for unauthorized viewing of data, bypassing authentication or the front-end application for direct XML database access, and possibly altering database information.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-250 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST SQL modules, PWN::Plugins::BurpSuite, PWN::Plugins::Fuzz; PWN::Plugins::OpenAPI, crafted XML via RestClient / TransparentBrowser; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-250 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-250`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the Target] Using a browser or an automated tool, an adversary records all instances of user-controllable input used to contruct XML queries | techniques: Use an automated tool to record all instances of user-controllable input used to contruct XML queries.; Use a browser to manually explore the website and analyze how the application processes inputs.
- Step 2 (Experiment): [Determine the Structure of Queries] Using manual or automated means, test inputs found for XML weaknesses. | techniques: Use XML reserved characters or words, possibly with other input data to attempt to cause unexpected results and identify improper input validation.
- Step 3 (Exploit): [Inject Content into XML Queries] Craft malicious content containing XML expressions that is not validated by the application and is executed as part of the XML queries. | techniques: Use the crafted input to execute unexpected queries that can disclose sensitive database information to the attacker.

## Prerequisites

- XML queries used to process user input and retrieve information stored in XML documents
- User-controllable input not properly sanitized

## Skills required

- Low: An attacker must have knowledge of XML syntax and constructs in order to successfully leverage XML Injection

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data

## Mitigations to bypass

- Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query.
- Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.

## Example instances (payload / topology hints)

- Consider an application that uses an XML database to authenticate its users. The application retrieves the user name and password from a request and forms an XPath expression to query the database. An attacker can successfully bypass authentication and login without valid credentials through XPath Injection. This can be achieved by injecting the query to the XML database with XPath syntax that ca…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-248](CAPEC-248.md)

## Related CWEs (run the cwe skill)

- [CWE-91](../cwe/references/CWE-91.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-707](../cwe/references/CWE-707.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-250 and CWE IDs
