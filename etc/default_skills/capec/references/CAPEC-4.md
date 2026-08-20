# CAPEC-4: Using Alternative IP Address Encodings

- Catalog: [CAPEC-4](https://capec.mitre.org/data/definitions/4.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack relies on the adversary using unexpected formats for representing IP addresses. Networked applications may expect network location information in a specific format, such as fully qualified domains names (FQDNs), URL, IP address, or IP Address ranges. If the location information is not validated against a variety of different possible encodings and formats, the adversary can use an alternate format to bypass application access control.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-4 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-4 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-4`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for IP addresses as user input] Using a browser, an automated tool or by inspecting the application, an adversary records all entry points to the application where IP addresses are used. | techniques: Use a spidering tool to follow and record all links and analyze the web pages to find entry points. Make special note of any links that include parameters i…
- Step 2 (Experiment): [Probe entry points to locate vulnerabilities] The adversary uses the entry points gathered in the "Explore" phase as a target list and attempts alternate IP address encodings, observing application behavior. The adversary will also attempt to access the application through an alternate IP address encoding to see if access control changes | techniques: Instead of using a URL,…
- Step 3 (Exploit): [Bypass access control] Using an alternate IP address encoding, the adversary will either access the application or give the alternate encoding as input, bypassing access control restrictions.

## Prerequisites

- The target software must fail to anticipate all of the possible valid encodings of an IP/web address.
- The adversary must have the ability to communicate with the server.

## Skills required

- Low: The adversary has only to try IP address format combinations.

## Resources required

- The adversary needs to have knowledge of an alternative IP address encoding that bypasses the access control policy of an application. Alternatively, the adversary can simply try to brute-force various encoding possibilities.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Design: Default deny access control policies
- Design: Input validation routines should check and enforce both input data types and content against a positive specification. In regards to IP addresses, this should include the authorized manner for the application to represent IP addresses and not accept user specified IP addresses and IP address formats (such as ranges)
- Implementation: Perform input validation for all remote content.

## Example instances (payload / topology hints)

- An adversary identifies an application server that applies a security policy based on the domain and application name. For example, the access control policy covers authentication and authorization for anyone accessing http://example.domain:8080/application. However, by using the IP address of the host instead (http://192.168.0.1:8080/application), the application authentication and authorization…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-267](CAPEC-267.md)

## Related CWEs (run the cwe skill)

- [CWE-291](../cwe/references/CWE-291.md) — run that CWE procedure after this CAPEC flow
- [CWE-173](../cwe/references/CWE-173.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-4 and CWE IDs
