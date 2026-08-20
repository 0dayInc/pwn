# CAPEC-83: XPath Injection

- Catalog: [CAPEC-83](https://capec.mitre.org/data/definitions/83.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker can craft special user-controllable input consisting of XPath expressions to inject the XML database and bypass authentication or glean information that they normally would not be able to. XPath Injection enables an attacker to talk directly to the XML database, thus bypassing the application completely. XPath Injection results from the failure of an application to properly sanitize input used as part of dynamic XPath expressions used to query an XML database.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-83 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::OpenAPI, crafted XML via RestClient / TransparentBrowser; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-83 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-83`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the target] Using a browser or an automated tool, an adversary records all instances of user-controllable input used to contruct XPath queries. | techniques: Use an automated tool to record all instances of user-controllable input used to contruct XPath queries.; Use a browser to manually explore the website and analyze how the application processes inputs.
- Step 2 (Explore): [Determine the tructure of queries] Using manual or automated means, test inputs found for XPath weaknesses. | techniques: Use an automated tool automatically probe the inputs for XPath weaknesses.; Manually probe the inputs using characters such as single quote (') that can cause XPath-releated errors, thus indicating an XPath weakness.
- Step 3 (Exploit): [Inject content into XPath query] Craft malicious content containing XPath expressions that is not validated by the application and is executed as part of the XPath queries. | techniques: Use the crafted input to execute unexpected queries that can disclose sensitive database information to the attacker.; Use a combination of single quote (') and boolean expressions such as "or…

## Prerequisites

- XPath queries used to retrieve information stored in XML documents
- User-controllable input not properly sanitized before being used as part of XPath queries

## Skills required

- Low: XPath Injection shares the same basic premises with SQL Injection. An attacker must have knowledge of XPath syntax and constructs in order to successfully leverage XPath Injection

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data

## Mitigations to bypass

- Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XPath expression. Characters such as a single-quote(') or operators such as or (|), and (&) and such should be filtered if the application does not expect them in the context in which they appear. If such content cannot be filt…
- Use of parameterized XPath queries - Parameterization causes the input to be restricted to certain domains, such as strings or integers, and any input outside such domains is considered invalid and the query fails.
- Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.

## Example instances (payload / topology hints)

- Consider an application that uses an XML database to authenticate its users. The application retrieves the user name and password from a request and forms an XPath expression to query the database. An attacker can successfully bypass authentication and login without valid credentials through XPath Injection. This can be achieved by injecting the query to the XML database with XPath syntax that ca…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-250](CAPEC-250.md)

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
- [ ] Finding (if any) cites CAPEC-83 and CWE IDs
