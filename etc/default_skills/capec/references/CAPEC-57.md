# CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data

- Catalog: [CAPEC-57](https://capec.mitre.org/data/definitions/57.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

This attack utilizes a REST(REpresentational State Transfer)-style applications' trust in the system resources and environment to obtain sensitive data once SSL is terminated.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-57 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-57 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-57`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find a REST-style application that uses SSL] The adversary must first find a REST-style application that uses SSL to target. Because this attack is easier to carry out from inside of a server network, it is likely that an adversary could have inside knowledge of how services operate.
- Step 2 (Experiment): [Insert a listener to sniff client-server communication] The adversary inserts a listener that must exist beyond the point where SSL is terminated. This can be placed on the client side if it is believed that sensitive information is being sent to the client as a response, although most often the listener will be placed on the server side to listen for client authentication i…
- Step 3 (Exploit): [Gather information passed in the clear] If developers have not hashed or encrypted data sent in the sniffed request, the adversary will be able to read this data in the clear. Most commonly, they will now have a username or password that they can use to submit requests to the web service just as an authorized user

## Prerequisites

- Opportunity to intercept must exist beyond the point where SSL is terminated.
- The adversary must be able to insert a listener actively (proxying the communication) or passively (sniffing the communication) in the client-server communication path.

## Skills required

- Low: To insert a network sniffer or other listener into the communication stream

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Implementation: Implement message level security such as HMAC in the HTTP communication
- Design: Utilize defense in depth, do not rely on a single security mechanism like SSL
- Design: Enforce principle of least privilege

## Example instances (payload / topology hints)

- The Rest service provider uses SSL to protect the communications between the service requester (client) to the service provider. In the instance where SSL is terminated before the communications reach the web server, it is very common in enterprise data centers to terminate SSL at a router, firewall, load balancer, proxy or other device, then the adversary can insert a sniffer into the communicat…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-157](CAPEC-157.md)

## Related CWEs (run the cwe skill)

- [CWE-300](../cwe/references/CWE-300.md) — run that CWE procedure after this CAPEC flow
- [CWE-287](../cwe/references/CWE-287.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-57 and CWE IDs
