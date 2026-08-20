# CAPEC-73: User-Controlled Filename

- Catalog: [CAPEC-73](https://capec.mitre.org/data/definitions/73.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attack of this type involves an adversary inserting malicious characters (such as a XSS redirection) into a filename, directly or indirectly that is then used by the target software to generate HTML text or other potentially executable content. Many websites rely on user-generated content and dynamically build resources like files, filenames, and URL links directly from user supplied data. In this attack pattern, the attacker uploads code that can execute in the client browser and/or redirect the client browser to a site that the attacker owns. All XSS attack payload variants can be used to pass and exploit these vulnerabilities.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-73 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser, PWN::Plugins::Zaproxy; PWN::Plugins::TransparentBrowser, PWN::Plugins::URIScheme

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-73 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-73`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The victim must trust the name and locale of user controlled filenames.

## Skills required

- Low: To achieve a redirection and use of less trusted source, an attacker can simply edit data that the host uses to build the filename
- Medium: Deploying a malicious "look-a-like" site (such as a site masquerading as a bank or online auction site) that the user enters their authentication data into.
- High: Exploiting a client side vulnerability to inject malicious scripts into the browser's executable process.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Availability: Alter Execution Logic
- Confidentiality: Read Data

## Mitigations to bypass

- Design: Use browser technologies that do not allow client side scripting.
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Perform input validation for all remote content.
- Implementation: Perform output validation for all remote content.
- Implementation: Disable scripting languages such as JavaScript in browser
- Implementation: Scan dynamically generated content against validation specification

## Example instances (payload / topology hints)

- Phishing attacks rely on a user clicking on links on that are supplied to them by attackers masquerading as a trusted resource such as a bank or online auction site. The end user's email client hosts the supplied resource name in this case via email. The resource name, however may either 1) direct the client browser to a malicious site to steal credentials and/or 2) execute code on the client mac…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-165](CAPEC-165.md)
- CanPrecede → [CAPEC-592](CAPEC-592.md)

## Related CWEs (run the cwe skill)

- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-184](../cwe/references/CWE-184.md) — run that CWE procedure after this CAPEC flow
- [CWE-96](../cwe/references/CWE-96.md) — run that CWE procedure after this CAPEC flow
- [CWE-348](../cwe/references/CWE-348.md) — run that CWE procedure after this CAPEC flow
- [CWE-116](../cwe/references/CWE-116.md) — run that CWE procedure after this CAPEC flow
- [CWE-350](../cwe/references/CWE-350.md) — run that CWE procedure after this CAPEC flow
- [CWE-86](../cwe/references/CWE-86.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-73 and CWE IDs
