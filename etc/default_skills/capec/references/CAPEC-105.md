# CAPEC-105: HTTP Request Splitting

- Catalog: [CAPEC-105](https://capec.mitre.org/data/definitions/105.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary abuses the flexibility and discrepancies in the parsing and interpretation of HTTP Request messages by different intermediary HTTP agents (e.g., load balancer, reverse proxy, web caching proxies, application firewalls, etc.) to split a single HTTP request into multiple unauthorized and malicious HTTP requests to a back-end HTTP agent (e.g., web server). See CanPrecede relationships for possible consequences.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-105 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-105 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-105`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey network to identify target] The adversary performs network reconnaissance by monitoring relevant traffic to identify the network path and parsing of the HTTP messages with the goal of identifying potential targets. | techniques: Scan networks to fingerprint HTTP infrastructure and monitor HTTP traffic to identify HTTP network path with a tool such as a Network Protocol A…
- Step 1 (Experiment): [Identify vulnerabilities in targeted HTTP infrastructure and technologies] The adversary sends a variety of benign/ambiguous HTTP requests to observe responses from HTTP infrastructure in order to identify differences/discrepancies in the interpretation and parsing of HTTP requests by examining supported HTTP protocol versions, HTTP headers, syntax checking and input filteri…
- Step 2 (Experiment): [Cause differential HTTP responses by experimenting with identified HTTP Request vulnerabilities] The adversary sends maliciously crafted HTTP requests with custom strings and embedded web scripts and objects in HTTP headers to interfere with the parsing of intermediary and back-end HTTP infrastructure, followed by normal/benign HTTP request from the adversary or a random use…
- Step 1 (Exploit): [Perform HTTP Request Splitting attack] Using knowledge discovered in the experiment section above, smuggle a message to cause one of the consequences. | techniques: Leverage techniques identified in the Experiment Phase.

## Prerequisites

- An additional intermediary HTTP agent such as an application firewall or a web caching proxy between the adversary and the second agent such as a web server, that sends multiple HTTP messages over same network connection.
- Differences in the way the two HTTP agents parse and interpret HTTP requests and its headers.
- HTTP headers capable of being user-manipulated.
- HTTP agents running on HTTP/1.0 or HTTP/1.1 that allow for Keep Alive mode, Pipelined queries, and Chunked queries and responses.

## Skills required

- Medium: Detailed knowledge on HTTP protocol: request and response messages structure and usage of specific headers.
- Medium: Detailed knowledge on how specific HTTP agents receive, send, process, interpret, and parse a variety of HTTP messages and headers.
- Medium: Possess knowledge on the exact details in the discrepancies between several targeted HTTP agents in path of an HTTP message in parsing its message structure and individual headers.

## Resources required

- Tools capable of crafting malicious HTTP messages and monitoring HTTP messages responses.

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Design: evaluate HTTP agents prior to deployment for parsing/interpretation discrepancies.
- Configuration: front-end HTTP agents notice ambiguous requests.
- Configuration: back-end HTTP agents reject ambiguous requests and close the network connection.
- Configuration: Disable reuse of back-end connections.
- Configuration: Use HTTP/2 for back-end connections.
- Configuration: Use the same web server software for front-end and back-end server.
- Implementation: Utilize a Web Application Firewall (WAF) that has built-in mitigation to detect abnormal requests/responses.
- Configuration: Install latest vendor security patches available for both intermediary and back-end HTTP infrastructure (i.e. proxies and web servers)
- Configuration: Ensure that HTTP infrastructure in the chain or network path utilize a strict uniform parsing process.
- Implementation: Utilize intermediary HTTP infrastructure capable of filtering and/or sanitizing user-input.

## Example instances (payload / topology hints)

- Microsoft Internet Explorer versions 5.01 SP4 and prior, 6.0 SP2 and prior, and 7.0 contain a vulnerability that could allow an unauthenticated, remote adversary to conduct HTTP request splitting and smuggling attacks. The vulnerability is due to an input validation error in the browser that allows adversaries to manipulate certain headers to expose the browser to HTTP request splitting and smugg…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-220](CAPEC-220.md)
- PeerOf → [CAPEC-34](CAPEC-34.md)
- CanPrecede → [CAPEC-115](CAPEC-115.md)
- CanPrecede → [CAPEC-141](CAPEC-141.md)
- CanPrecede → [CAPEC-63](CAPEC-63.md)
- CanPrecede → [CAPEC-593](CAPEC-593.md)
- CanPrecede → [CAPEC-148](CAPEC-148.md)
- CanPrecede → [CAPEC-154](CAPEC-154.md)

## Related CWEs (run the cwe skill)

- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-113](../cwe/references/CWE-113.md) — run that CWE procedure after this CAPEC flow
- [CWE-138](../cwe/references/CWE-138.md) — run that CWE procedure after this CAPEC flow
- [CWE-436](../cwe/references/CWE-436.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-105 and CWE IDs
