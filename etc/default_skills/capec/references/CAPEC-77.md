# CAPEC-77: Manipulating User-Controlled Variables

- Catalog: [CAPEC-77](https://capec.mitre.org/data/definitions/77.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

This attack targets user controlled variables (DEBUG=1, PHP Globals, and So Forth). An adversary can override variables leveraging user-supplied, untrusted query variables directly used on the application server without any data sanitization. In extreme cases, the adversary can change variables controlling the business logic of the application. For instance, in languages like PHP, a number of poorly set default configurations may allow the user to override variables.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-77 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-77 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-77`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Probe target application] The adversary first probes the target application to determine important information about the target. This information could include types software used, software versions, what user input the application consumes, and so on.
- Step 2 (Experiment): [Find user-controlled variables] Using the information found by probing the application, the adversary attempts to manipulate many user-controlled variables and observes the effects on the application. If the adversary notices any significant changes to the application, they will know that a certain variable is useful to the application. | techniques: Adversaries will try to…
- Step 3 (Exploit): [Manipulate user-controlled variables] Once the adversary has found a user-controller variable(s) that is important to the application, they will manipulate it to change the normal behavior in a way that benefits the adversary.

## Prerequisites

- A variable consumed by the application server is exposed to the client.
- A variable consumed by the application server can be overwritten by the user.
- The application server trusts user supplied data to compute business logic.
- The application server does not perform proper input validation.

## Skills required

- Low: The malicious user can easily try some well-known global variables and find one which matches.
- Medium: The adversary can use automated tools to probe for variables that they can control.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Do not allow override of global variables and do Not Trust Global Variables. If the register_globals option is enabled, PHP will create global variables for each GET, POST, and cookie variable included in the HTTP request. This means that a malicious user may be able to set variables unexpectedly. For instance make sure that the server setting for PHP does not expose global variables.
- A software system should be reluctant to trust variables that have been initialized outside of its trust boundary. Ensure adequate checking is performed when relying on input from outside a trust boundary.
- Separate the presentation layer and the business logic layer. Variables at the business logic layer should not be exposed at the presentation layer. This is to prevent computation of business logic from user controlled input data.
- Use encapsulation when declaring your variables. This is to lower the exposure of your variables.
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should be rejected by the program.

## Example instances (payload / topology hints)

- PHP is a study in bad security. The main idea pervading PHP is "ease of use," and the mantra "don't make the developer go to any extra work to get stuff done" applies in all cases. This is accomplished in PHP by removing formalism from the language, allowing declaration of variables on first use, initializing everything with preset values, and taking every meaningful variable from a transaction a…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-22](CAPEC-22.md)

## Related CWEs (run the cwe skill)

- [CWE-15](../cwe/references/CWE-15.md) — run that CWE procedure after this CAPEC flow
- [CWE-94](../cwe/references/CWE-94.md) — run that CWE procedure after this CAPEC flow
- [CWE-96](../cwe/references/CWE-96.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-302](../cwe/references/CWE-302.md) — run that CWE procedure after this CAPEC flow
- [CWE-473](../cwe/references/CWE-473.md) — run that CWE procedure after this CAPEC flow
- [CWE-1321](../cwe/references/CWE-1321.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-77 and CWE IDs
