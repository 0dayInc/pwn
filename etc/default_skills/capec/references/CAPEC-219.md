# CAPEC-219: XML Routing Detour Attacks

- Catalog: [CAPEC-219](https://capec.mitre.org/data/definitions/219.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An attacker subverts an intermediate system used to process XML content and forces the intermediate to modify and/or re-route the processing of the content. XML Routing Detour Attacks are Adversary in the Middle type attacks (CAPEC-94). The attacker compromises or inserts an intermediate system in the processing of the XML message. For example, WS-Routing can be used to specify a series of nodes or intermediaries through which content is passed. If any of the intermediate nodes in this route are compromised by an attacker they could be used for a routing detour attack. From the compromised system the attacker is able to route the XML process to other nodes of their choice and modify the responses so that the normal chain of processing is unaware of the interception. This system can forward the message to an outside entity and hide the forwarding and processing from the legitimate processing systems by altering the header information.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-219 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::OpenAPI, crafted XML via RestClient / TransparentBrowser

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-219 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-219`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the target] Using command line or an automated tool, an attacker records all instances of web services to process XML requests. | techniques: Use automated tool to record all instances to process XML requests or find exposed WSDL.; Use tools to crawl WSDL
- Step 2 (Experiment): [Identify SOAP messages that have multiple state processing.] Inspect instance to see whether the XML processing has multiple stages or not. | techniques: Inspect the SOAP message routing head to see whether the XML processing has multiple stages or not.
- Step 3 (Exploit): [Launch an XML routing detour attack] The attacker injects a bogus routing node (using a WS-Referral service) into the routing table of the XML header of the SOAP message identified in the Explore phase. Thus, the attacker can route the XML message to the attacker controlled node (and access the message contents). | techniques: The attacker injects a bogus routing node (using a…

## Prerequisites

- The targeted system must have multiple stages processing of XML content.

## Skills required

- Low: To inject a bogus node in the XML routing table

## Resources required

- The attacker must be able to insert or compromise a system into the processing path for the transaction.

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Design: Specify maximum number intermediate nodes for the request and require SSL connections with mutual authentication.
- Implementation: Use SSL for connections between all parties with mutual authentication.

## Example instances (payload / topology hints)

- Here is an example SOAP call from a client, example1.com, to a target, example4.com, via 2 intermediaries, example2.com and example3.com. (note: The client here is not necessarily a 'end user client' but rather the starting point of the XML transaction). Example SOAP message with routing information in header: <S:Envelope> <S:Header> <m:path xmlns:m="http://schemas.example.com/rp/" S:actor="http:…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-94](CAPEC-94.md)

## Related CWEs (run the cwe skill)

- [CWE-441](../cwe/references/CWE-441.md) — run that CWE procedure after this CAPEC flow
- [CWE-610](../cwe/references/CWE-610.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-219 and CWE IDs
