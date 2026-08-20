# CAPEC-201: Serialized Data External Linking

- Catalog: [CAPEC-201](https://capec.mitre.org/data/definitions/201.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary creates a serialized data file (e.g. XML, YAML, etc...) that contains an external data reference. Because serialized data parsers may not validate documents with external references, there may be no checks on the nature of the reference in the external data. This can allow an adversary to open arbitrary files or connections, which may further lead to the adversary gaining access to information on the system that they would normally be unable to obtain.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-201 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::OpenAPI, crafted XML via RestClient / TransparentBrowser

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-201 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-201`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the target] Using a browser or an automated tool, an adversary records all instances of web services that process requests with serialized data. | techniques: Use an automated tool to record all instances of URLs that process requests with serialized data.; Use a browser to manually explore the website and analyze how the application processes serialized data requests.
- Step 2 (Exploit): [Craft malicious payload] The adversary crafts malicious data message that contains references to sensitive files.
- Step 3 (Exploit): [Launch an External Linking attack] Send the malicious crafted message containing the reference to a sensitive file to the target URL.

## Prerequisites

- The target must follow external data references without validating the validity of the reference target.

## Skills required

- Low: To send serialized data messages with maliciously crafted schema.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- Configure the serialized data processor to only retrieve external entities from trusted sources.

## Example instances (payload / topology hints)

- The following DTD would attempt to open the /dev/tty device: <!DOCTYPE doc [ <!ENTITY ent SYSTEM "file:///dev/tty"> ]> A malicious actor could use this crafted DTD to reveal sensitive information.
- The following XML snippet would attempt to open the /etc/passwd file: <foo xmlns:xi="http://www.w3.org/2001/XInclude"> <xi:include parse="text" href="file:///etc/passwd"/></foo>

## Related CAPECs (test these too)

- ChildOf → [CAPEC-122](CAPEC-122.md)
- ChildOf → [CAPEC-278](CAPEC-278.md)

## Related CWEs (run the cwe skill)

- [CWE-829](../cwe/references/CWE-829.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-201 and CWE IDs
