# CAPEC-146: XML Schema Poisoning

- Catalog: [CAPEC-146](https://capec.mitre.org/data/definitions/146.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary corrupts or modifies the content of XML schema information passed between a client and server for the purpose of undermining the security of the target. XML Schemas provide the structure and content definitions for XML documents. Schema poisoning is the ability to manipulate a schema either by replacing or modifying it to compromise the programs that process documents that use this schema.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-146 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::OpenAPI, crafted XML via RestClient / TransparentBrowser

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-146 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-146`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine if XML schema is local or remote] Because this attack differs slightly if the target uses remote XML schemas versus local schemas, the adversary first needs to determine which of the two are used.
- Step 2 (Experiment): [Gain access to XML schema] The adversary gains access to the XML schema so that they can modify the contents. | techniques: For a local scenario, the adversary needs access to the machine that the schema is located on and needs to gain permissions to alter the contents of the file.; For a remote scenario, the adversary needs to be able to sniff HTTP traffic that contains an…
- Step 3 (Exploit): [Poison XML schema] Once the adversary gains access to the XML schema, they will alter it to achieve a desired effect. Locally, they can simply modify the file. For remote schemas, the adversary will alter the schema in transit by performing an adversary in the middle attack. | techniques: Cause a denial of service by modifying the schema so that it does not contain required inf…

## Prerequisites

- Some level of access to modify the target schema.
- The schema used by the target application must be improperly secured against unauthorized modification and manipulation.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- Access to the schema and the knowledge and ability modify it. Ability to replace or redirect access to the modified schema.

## Oracles (consequences)

- Availability: Unreliable Execution, Resource Consumption — A successful schema poisoning attack can compromise the availability of the target system's service by exhausting its available resources.
- Integrity: Modify Data
- Confidentiality: Read Data

## Mitigations to bypass

- Design: Protect the schema against unauthorized modification.
- Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the XML document. Additionally, ensure that the proper permissions are set on local files to avoid unauthorized modification.
- Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

## Example instances (payload / topology hints)

- XML Schema Poisoning Attacks can often occur locally due to being embedded within the XML document itself or being located on the host within an improperaly protected file. In these cases, the adversary can simply edit the XML schema without the need for additional privileges. An example of the former can be seen below: <?xml version="1.0"?> <!DOCTYPE contact [ <!ELEMENT contact (name,phone,email…
- XML Schema Poisoning Attacks can also be executed remotely if the HTTP protocol is being used to transport data. : <?xml version="1.0"?> <!DOCTYPE contact SYSTEM "http://example.com/contact.dtd"[ <note> <name>John Smith</name> <phone>555-1234</phone> <email>jsmith@email.com</email> <address>1 Example Lane</address> </note></capec:Code> The HTTP protocol does not encrypt the traffic it transports,…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-271](CAPEC-271.md)

## Related CWEs (run the cwe skill)

- [CWE-15](../cwe/references/CWE-15.md) — run that CWE procedure after this CAPEC flow
- [CWE-472](../cwe/references/CWE-472.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-146 and CWE IDs
