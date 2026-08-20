# CAPEC-136: LDAP Injection

- Catalog: [CAPEC-136](https://capec.mitre.org/data/definitions/136.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker manipulates or crafts an LDAP query for the purpose of undermining the security of the target. Some applications use user input to create LDAP queries that are processed by an LDAP server. For example, a user might provide their username during authentication and the username might be inserted in an LDAP query during the authentication process. An attacker could use this input to inject additional commands into an LDAP query that could disclose sensitive information. For example, entering a * in the aforementioned query might return information about all users on the system. This attack is very similar to an SQL injection attack in that it manipulates a query to gather additional information or coerce a particular return value.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-136 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST SQL modules, PWN::Plugins::BurpSuite, PWN::Plugins::Fuzz; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-136 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-136`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey application] The attacker takes an inventory of the entry points of the application. | techniques: Spider web sites for all available links; Sniff network communications with application using a utility such as WireShark.
- Step 2 (Experiment): [Determine user-controllable input susceptible to LDAP injection] For each user-controllable input that the attacker suspects is vulnerable to LDAP injection, attempt to inject characters that have special meaning in LDAP (such as a single quote character, etc.). The goal is to create a LDAP query with an invalid syntax | techniques: Use web browser to inject input through te…
- Step 3 (Experiment): [Try to exploit the LDAP injection vulnerability] After determining that a given input is vulnerable to LDAP Injection, hypothesize what the underlying query looks like. Possibly using a tool, iteratively try to add logic to the query to extract information from the LDAP, or to modify or delete information in the LDAP. | techniques: Add logic to the LDAP query to change the m…

## Prerequisites

- The target application must accept a string as user input, fail to sanitize characters that have a special meaning in LDAP queries in the user input, and insert the user-supplied string in an LDAP query which is then processed.

## Skills required

- Medium: The attacker needs to have knowledge of LDAP, especially its query syntax.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Availability: Unreliable Execution
- Integrity: Modify Data
- Confidentiality: Read Data
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content.
- Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

## Example instances (payload / topology hints)

- PowerDNS before 2.9.18, when running with an LDAP backend, does not properly escape LDAP queries, which allows remote attackers to cause a denial of service (failure to answer ldap questions) and possibly conduct an LDAP injection attack. See also: CVE-2005-2301

## Related CAPECs (test these too)

- ChildOf → [CAPEC-248](CAPEC-248.md)

## Related CWEs (run the cwe skill)

- [CWE-77](../cwe/references/CWE-77.md) — run that CWE procedure after this CAPEC flow
- [CWE-90](../cwe/references/CWE-90.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-136 and CWE IDs
