# CAPEC-279: SOAP Manipulation

- Catalog: [CAPEC-279](https://capec.mitre.org/data/definitions/279.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

Simple Object Access Protocol (SOAP) is used as a communication protocol between a client and server to invoke web services on the server. It is an XML-based protocol, and therefore suffers from many of the same shortcomings as other XML-based protocols. Adversaries can make use of these shortcomings and manipulate the content of SOAP paramters, leading to undesirable behavior on the server and allowing the adversary to carry out a number of further attacks.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-279 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::OpenAPI, crafted XML via RestClient / TransparentBrowser

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-279 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-279`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Exploit): [Find target application] The adversary needs to identify an application that uses SOAP as a communication protocol. | techniques: Observe HTTP traffic to an application and look for SOAP headers.
- Step 2 (Experiment): [Detect Incorrect SOAP Parameter Handling] The adversary tampers with the SOAP message parameters and looks for indications that the tampering caused a change in behavior of the targeted application. | techniques: Send more data than would seem reasonable for a field and see if the server complains.; Send nonsense data in a field that expects a certain subset, such as product…
- Step 3 (Exploit): [Manipulate SOAP parameters] The adversary manipulates SOAP parameters in a way that causes undesirable behavior for the server. This can result in denial of service, information disclosure, arbitrary code exection, and more. | techniques: Create a recursive XML payload that will take up all of the memory on the server when parsed, resulting in a denial of service. This is known…

## Prerequisites

- An application uses SOAP-based web service api.
- An application does not perform sufficient input validation to ensure that user-controllable data is safe for an XML parser.
- The targeted server either fails to verify that data in SOAP messages conforms to the appropriate XML schema, or it fails to correctly handle the complete range of data allowed by the schema.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Availability: Resource Consumption
- Confidentiality: Read Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-278](CAPEC-278.md)
- CanPrecede → [CAPEC-110](CAPEC-110.md)
- CanPrecede → [CAPEC-228](CAPEC-228.md)

## Related CWEs (run the cwe skill)

- [CWE-707](../cwe/references/CWE-707.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-279 and CWE IDs
