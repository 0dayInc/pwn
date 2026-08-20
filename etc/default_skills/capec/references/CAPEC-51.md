# CAPEC-51: Poison Web Service Registry

- Catalog: [CAPEC-51](https://capec.mitre.org/data/definitions/51.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

SOA and Web Services often use a registry to perform look up, get schema information, and metadata about services. A poisoned registry can redirect (think phishing for servers) the service requester to a malicious service provider, provide incorrect information in schema or metadata, and delete information about service provider interfaces.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-51 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::TransparentBrowser, PWN::Plugins::URIScheme; social-engineering skill, PWN::Plugins::MailAgent

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-51 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-51`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find a target SOA or Web Service] The adversary must first indentify a target SOA or Web Service.
- Step 2 (Experiment): [Determine desired outcome] Because poisoning a web service registry can have different outcomes, the adversary must decide how they wish to effect the webservice. | techniques: An adversary can perform a denial of service attack on a web service.; An adversary can redirect requests or responses to a malicious service.
- Step 3 (Experiment): [Determine if a malicious service needs to be created] If the adversary wishes to redirect requests or responses, they will need to create a malicious service to redirect to. | techniques: Create a service to that requests are sent to in addition to the legitimate service and simply record the requests.; Create a service that will give malicious responses to a service provide…
- Step 4 (Exploit): [Poison Web Service Registry] Based on the desired outcome, poison the web service registry. This is done by altering the data at rest in the registry or uploading malicious content by spoofing a service provider. | techniques: Intercept and change WS-Adressing headers to route to a malicious service or service provider.; Provide incorrect information in schema or metadata to ca…

## Prerequisites

- The attacker must be able to write to resources or redirect access to the service registry.

## Skills required

- Low: To identify and execute against an over-privileged system interface

## Resources required

- Capability to directly or indirectly modify registry resources

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Design: Enforce principle of least privilege
- Design: Harden registry server and file access permissions
- Implementation: Implement communications to and from the registry using secure protocols

## Example instances (payload / topology hints)

- WS-Addressing provides location and metadata about the service endpoints. An extremely hard to detect attack is an attacker who updates the WS-Addressing header, leaves the standard service request and service provider addressing and header information intact, but adds an additional WS-Addressing Replyto header. In this case the attacker is able to send a copy (like a cc in mail) of every result…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-203](CAPEC-203.md)

## Related CWEs (run the cwe skill)

- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-51 and CWE IDs
