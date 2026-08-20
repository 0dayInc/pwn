# CAPEC-147: XML Ping of the Death

- Catalog: [CAPEC-147](https://capec.mitre.org/data/definitions/147.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An attacker initiates a resource depletion attack where a large number of small XML messages are delivered at a sufficiently rapid rate to cause a denial of service or crash of the target. Transactions such as repetitive SOAP transactions can deplete resources faster than a simple flooding attack because of the additional resources used by the SOAP protocol and the resources necessary to process SOAP messages. The transactions used are immaterial as long as they cause resource utilization on the target. In other words, this is a normal flooding attack augmented by using messages that will require extra processing on the target.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-147 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::OpenAPI, crafted XML via RestClient / TransparentBrowser

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-147 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-147`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the target] Using a browser or an automated tool, an attacker records all instance of web services to process XML requests. | techniques: Use an automated tool to record all instances of URLs to process XML requests.; Use a browser to manually explore the website and analyze how the application processes XML requests.
- Step 2 (Exploit): [Launch a resource depletion attack] The attacker delivers a large number of small XML messages to the target URLs found in the explore phase at a sufficiently rapid rate. It causes denial of service to the target application. | techniques: Send a large number of crafted small XML messages to the target URL.

## Prerequisites

- The target must receive and process XML transactions.

## Skills required

- Low: To send small XML messages
- High: To use distributed network to launch the attack

## Resources required

- Transaction generator(s)/source(s) and ability to cause arrival of messages at the target with sufficient rapidity to overload target. Larger targets may be able to handle large volumes of requests so the attacker may require significant resources (such as a distributed network) to affect the target. However, the resources required of the attacker would be less than in the case of a simple floodi…

## Oracles (consequences)

- Availability: Resource Consumption — DoS: resource consumption (other)

## Mitigations to bypass

- Design: Build throttling mechanism into the resource allocation. Provide for a timeout mechanism for allocated resources whose transaction does not complete within a specified interval.
- Implementation: Provide for network flow control and traffic shaping to control access to the resources.

## Example instances (payload / topology hints)

- Consider the case of attack performed against the createCustomerBillingAccount Web Service for an online store. In this case, the createCustomerBillingAccount Web Service receives a huge number of simultaneous requests, containing nonsense billing account creation information (the small XML messages). The createCustomerBillingAccount Web Services may forward the messages to other Web Services for…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-528](CAPEC-528.md)

## Related CWEs (run the cwe skill)

- [CWE-400](../cwe/references/CWE-400.md) — run that CWE procedure after this CAPEC flow
- [CWE-770](../cwe/references/CWE-770.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-147 and CWE IDs
