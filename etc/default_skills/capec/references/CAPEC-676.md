# CAPEC-676: NoSQL Injection

- Catalog: [CAPEC-676](https://capec.mitre.org/data/definitions/676.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary targets software that constructs NoSQL statements based on user input or with parameters vulnerable to operator replacement in order to achieve a variety of technical impacts such as escalating privileges, bypassing authentication, and/or executing code.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-676 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST SQL modules, PWN::Plugins::BurpSuite, PWN::Plugins::Fuzz; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-676 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-676`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey target application] Due to the number of NoSQL databases available and the numerous language/API combinations of each, the adversary must first survey the target application to learn what technologies are being leveraged and how they interact with user-driven data. | techniques: Determine the technology stack leveraged by the target application, such as the application s…
- Step 2 (Experiment): [Identify user-controllable input susceptible to injection] After identifying the technology stack being used and where user-driven input is leveraged, determine the user-controllable input susceptible to injection such as authentication or search forms. For each user-controllable input that the adversary suspects is vulnerable to NoSQL injection, attempt to inject characters…
- Step 3 (Experiment): [Experiment with NoSQL Injection vulnerabilities] After determining that a given input is vulnerable to NoSQL Injection, hypothesize what the underlying query looks like. Iteratively try to add logic to the query to extract information from the database, modify/delete information in the database, or execute commands on the server. | techniques: Use public resources such as OW…
- Step 4 (Exploit): [Exploit NoSQL Injection vulnerability] After refining and adding various logic to NoSQL queries, craft and execute the underlying NoSQL query that will be used to attack the target system. | techniques: Craft and Execute underlying NoSQL query

## Prerequisites

- Awareness of the technology stack being leveraged by the target application.
- NoSQL queries used by the application to store, retrieve, or modify data.
- User-controllable input that is not properly validated by the application as part of NoSQL queries.
- Target potentially susceptible to operator replacement attacks.

## Skills required

- Low: For keyword and JavaScript injection attacks, it is fairly simple for someone with basic NoSQL knowledge to perform NoSQL injection, once the target's technology stack has been determined.
- Medium: For operator replacement attacks, the adversary must also have knowledge of HTTP Parameter Pollution attacks and how to conduct them.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as relevant NoSQL and JavaScript content. NoSQL-specific keywords, such as $ne, $eq or $gt for MongoDB, must be filtered in addition to characters such as a single-quote(') or semicolons (;) based on the context in which they appear. Validation should also extend to expected types.
- If possible, leverage safe APIs (e.g., PyMongo and Flask-PyMongo for Python and MongoDB) for queries as opposed to building queries from strings.
- Ensure the most recent version of a NoSQL database and it's corresponding API are used by the application.
- Use of custom error pages - Adversaries can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.
- Exercise the principle of Least Privilege with regards to application accounts to minimize damage if a NoSQL injection attack is successful.
- If using MongoDB, disable server-side JavaScript execution and leverage a sanitization module such as "mongo-sanitize".
- If using PHP with MongoDB, ensure all special query operators (starting with $) use single quotes to prevent operator replacement attacks.
- Additional mitigations will depend on the NoSQL database, API, and programming language leveraged by the application.

## Example instances (payload / topology hints)

- The following examples primarily cite MongoDB, PHP, and NodeJS attacks due to their prominence and popularity. However, please note that these attacks are not exclusive to this NoSQL instance, programming language, or runtime framework. Within NodeJS, Login Bypass attacks are possible via MongoDB if user-input is not properly validated and sanitized [REF-670]. //NodeJS with Express.js db.collecti…
- MongoDB instances are also vulnerable to JavaScript Injection Attacks when user input is not properly validated and sanitized. //PHP with MongoDB db.collection.find({$where: function() { return (this.username == $username) } } ); If the user properly specifies a username, then this code will execute as intended. However, an adversary can inject JavaScript into the "$username" variable to achieve…
- If leveraging PHP with MongoDB, operator replacement attacks are possible if special query operators are not properly addressed. The below example from OWASP's "Test for NoSQL Injection" displays a simple case of how this could occur.[REF-668] db.myCollection.find({$where: function() { return obj.credits - obj.debits < 0; } } ); Even though the above query does not depend on any user input, it is…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-248](CAPEC-248.md)

## Related CWEs (run the cwe skill)

- [CWE-943](../cwe/references/CWE-943.md) — run that CWE procedure after this CAPEC flow
- [CWE-1286](../cwe/references/CWE-1286.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-676 and CWE IDs
