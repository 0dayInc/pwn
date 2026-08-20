# CAPEC-48: Passing Local Filenames to Functions That Expect a URL

- Catalog: [CAPEC-48](https://capec.mitre.org/data/definitions/48.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack relies on client side code to access local files and resources instead of URLs. When the client browser is expecting a URL string, but instead receives a request for a local file, that execution is likely to occur in the browser process space with the browser's authority to local files. The attacker can send the results of this request to the local files out to a site that they control. This attack may be used to steal sensitive authentication data (either local or remote), or to gain system profile information to launch further attacks.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-48 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-48 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-48`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify web application URL inputs] Review application inputs to find those that are designed to be URLs. | techniques: Manually navigate web site pages to identify URLs.; Use automated tools to identify URLs.
- Step 2 (Experiment): [Identify URL inputs allowing local access.] Execute test local commands via each URL input to determine which are successful. | techniques: Manually execute a local command (such as 'pwd') via the URL inputs.; Using an automated tool, test each URL input for weakness.
- Step 3 (Exploit): [Execute malicious commands] Using the identified URL inputs that allow local command execution, execute malicious commands. | techniques: Execute local commands via the URL input.

## Prerequisites

- The victim's software must not differentiate between the location and type of reference passed the client software, e.g. browser

## Skills required

- Medium: Attacker identifies known local files to exploit

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Ensure all configuration files and resource are either removed or protected when promoting code into production.
- Design: Use browser technologies that do not allow client side scripting.
- Implementation: Perform input validation for all remote content.
- Implementation: Perform output validation for all remote content.
- Implementation: Disable scripting languages such as JavaScript in browser

## Example instances (payload / topology hints)

- J2EE applications frequently use .properties files to store configuration information including JDBC connections, LDAP connection strings, proxy information, system passwords and other system metadata that is valuable to attackers looking to probe the system or bypass policy enforcement points. When these files are stored in publicly accessible directories and are allowed to be read by the public…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-212](CAPEC-212.md)

## Related CWEs (run the cwe skill)

- [CWE-241](../cwe/references/CWE-241.md) — run that CWE procedure after this CAPEC flow
- [CWE-706](../cwe/references/CWE-706.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-48 and CWE IDs
