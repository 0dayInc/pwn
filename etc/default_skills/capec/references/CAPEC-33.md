# CAPEC-33: HTTP Request Smuggling

- Catalog: [CAPEC-33](https://capec.mitre.org/data/definitions/33.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary abuses the flexibility and discrepancies in the parsing and interpretation of HTTP Request messages using various HTTP headers, request-line and body parameters as well as message sizes (denoted by the end of message signaled by a given HTTP header) by different intermediary HTTP agents (e.g., load balancer, reverse proxy, web caching proxies, application firewalls, etc.) to secretly send unauthorized and malicious HTTP requests to a back-end HTTP agent (e.g., web server). See CanPrecede relationships for possible consequences.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-33 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-33 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-33`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey network to identify target] The adversary performs network reconnaissance by monitoring relevant traffic to identify the network path and parsing of the HTTP messages with the goal of identifying potential targets. | techniques: Scan networks to fingerprint HTTP infrastructure and monitor HTTP traffic to identify HTTP network path with a tool such as a Network Protocol A…
- Step 1 (Experiment): [Identify vulnerabilities in targeted HTTP infrastructure and technologies] The adversary sends a variety of benign/ambiguous HTTP requests to observe responses from HTTP infrastructure in order to identify differences/discrepancies in the interpretation and parsing of HTTP requests by examining supported HTTP protocol versions, message sizes, and HTTP headers.
- Step 2 (Experiment): [Cause differential HTTP responses by experimenting with identified HTTP Request vulnerabilities] The adversary sends maliciously crafted HTTP requests to interfere with the parsing of intermediary and back-end HTTP infrastructure, followed by normal/benign HTTP request from the adversary or a random user. The intended consequences of the malicious HTTP requests will be obser…
- Step 1 (Exploit): [Perform HTTP Request Smuggling attack] Using knowledge discovered in the experiment section above, smuggle a message to cause one of the consequences. | techniques: Leverage techniques identified in the Experiment Phase.

## Prerequisites

- An additional intermediary HTTP agent such as an application firewall or a web caching proxy between the adversary and the second agent such as a web server, that sends multiple HTTP messages over same network connection.
- Differences in the way the two HTTP agents parse and interpret HTTP requests and its headers.
- HTTP agents running on HTTP/1.1 that allow for Keep Alive mode, Pipelined queries, and Chunked queries and responses.

## Skills required

- Medium: Detailed knowledge on HTTP protocol: request and response messages structure and usage of specific headers.
- Medium: Detailed knowledge on how specific HTTP agents receive, send, process, interpret, and parse a variety of HTTP messages and headers.
- Medium: Possess knowledge on the exact details in the discrepancies between several targeted HTTP agents in path of an HTTP message in parsing its message structure and individual headers.

## Resources required

- Tools capable of crafting malicious HTTP messages and monitoring HTTP message responses.

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization: Gain Privileges
- Integrity: Modify Data

## Mitigations to bypass

- Design: evaluate HTTP agents prior to deployment for parsing/interpretation discrepancies.
- Configuration: front-end HTTP agents notice ambiguous requests.
- Configuration: back-end HTTP agents reject ambiguous requests and close the network connection.
- Configuration: Disable reuse of back-end connections.
- Configuration: Use HTTP/2 for back-end connections.
- Configuration: Use the same web server software for front-end and back-end server.
- Implementation: Utilize a Web Application Firewall (WAF) that has built-in mitigation to detect abnormal requests/responses.
- Configuration: Prioritize Transfer-Encoding header over Content-Length, whenever an HTTP message contains both.
- Configuration: Disallow HTTP messages with both Transfer-Encoding and Content-Length or Double Content-Length Headers.
- Configuration: Disallow Malformed/Invalid Transfer-Encoding Headers used in obfuscation, such as: Headers with no space before the value “chunked” Headers with extra spaces Headers beginning with trailing characters Headers providing a value “chunk” instead of “chunked” (the server normalizes this as chunked encoding) Headers with multiple spaces before the value “chunked” Headers with quoted val…
- Configuration: Install latest vendor security patches available for both intermediary and back-end HTTP infrastructure (i.e. proxies and web servers)
- Configuration: Ensure that HTTP infrastructure in the chain or network path utilize a strict uniform parsing process.
- Implementation: Utilize intermediary HTTP infrastructure capable of filtering and/or sanitizing user-input.

## Example instances (payload / topology hints)

- When using Haproxy 1.5.3 version as front-end proxy server with with Node.js version 14.13.1 or 12.19.0 as the back-end web server it is possible to use two same header fields for example: two Transfer-Encoding, Transfer-Encoding: chunked and Transfer-Encoding: chunked-false, to bypass Haproxy /flag URI restriction and receive the Haproxy flag value, since Node.js identifies the first header but…
- When using Sun Java System Web Proxy Server 3.x or 4.x in conjunction with Sun ONE/iPlanet 6.x, Sun Java System Application Server 7.x or 8.x, it is possible to bypass certain application firewall protections, hijack web sessions, perform Cross Site Scripting or poison the web proxy cache using HTTP Request Smuggling. Differences in the way HTTP requests are parsed by the Proxy Server and the App…
- Apache server 2.0.45 and version before 1.3.34, when used as a proxy, easily lead to web cache poisoning and bypassing of application firewall restrictions because of non-standard HTTP behavior. Although the HTTP/1.1 specification clearly states that a request with both "Content-Length" and a "Transfer-Encoding: chunked" headers is invalid, vulnerable versions of Apache accept such requests and r…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-220](CAPEC-220.md)
- PeerOf → [CAPEC-273](CAPEC-273.md)
- CanPrecede → [CAPEC-115](CAPEC-115.md)
- CanPrecede → [CAPEC-141](CAPEC-141.md)
- CanPrecede → [CAPEC-63](CAPEC-63.md)
- CanPrecede → [CAPEC-593](CAPEC-593.md)
- CanPrecede → [CAPEC-148](CAPEC-148.md)
- CanPrecede → [CAPEC-154](CAPEC-154.md)

## Related CWEs (run the cwe skill)

- [CWE-444](../cwe/references/CWE-444.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-33 and CWE IDs
