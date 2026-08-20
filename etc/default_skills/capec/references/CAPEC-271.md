# CAPEC-271: Schema Poisoning

- Catalog: [CAPEC-271](https://capec.mitre.org/data/definitions/271.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary corrupts or modifies the content of a schema for the purpose of undermining the security of the target. Schemas provide the structure and content definitions for resources used by an application. By replacing or modifying a schema, the adversary can affect how the application handles or interprets a resource, often leading to possible denial of service, entering into an unexpected state, or recording incomplete data.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-271 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-271 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-271`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find target application and schema] The adversary first finds the application that they want to target. This application must use schemas in some way, so the adversary also needs to confirm that schemas are being used. | techniques: Gain access to the system that the application is on and look for a schema.; Observe HTTP traffic to the application and look for a schema being tr…
- Step 2 (Experiment): [Gain access to schema] The adversary gains access to the schema so that they can modify the contents. | techniques: For a local scenario, the adversary needs access to the machine that the schema is located on and gain permissions to alter the contents of the schema file.; For a remote scenario, the adversary needs to be able to perform an adversary in the middle attack on t…
- Step 3 (Exploit): [Poison schema] Once the adversary gains access to the schema, they will alter it to achieve a desired effect. Locally, they can just modify the file. For remote schemas, the adversary will alter the schema in transit by performing an adversary in the middle attack. | techniques: Cause a denial of service by modifying the schema so that it does not contain required information f…

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
- Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.
- Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

## Example instances (payload / topology hints)

- In a JSON Schema Poisoning Attack, an adervary modifies the JSON schema to cause a Denial of Service (DOS) or to submit malicious input: { "title": "Contact", "type": "object", "properties": { "Name": { "type": "string" }, "Phone": { "type": "string" }, "Email": { "type": "string" }, "Address": { "type": "string" } }, "required": ["Name", "Phone", "Email", "Address"] } If the 'name' attribute is…
- In a Database Schema Poisoning Attack, an adversary alters the database schema being used to modify the database in some way. This can result in loss of data, DOS, or malicious input being submitted. Assuming there is a column named "name", an adversary could make the following schema change: ALTER TABLE Contacts MODIFY Name VARCHAR(65353); The "Name" field of the "Conteacts" table now allows the…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-176](CAPEC-176.md)
- CanFollow → [CAPEC-94](CAPEC-94.md)

## Related CWEs (run the cwe skill)

- [CWE-15](../cwe/references/CWE-15.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-271 and CWE IDs
