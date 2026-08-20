# CAPEC-273: HTTP Response Smuggling

- Catalog: [CAPEC-273](https://capec.mitre.org/data/definitions/273.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary manipulates and injects malicious content in the form of secret unauthorized HTTP responses, into a single HTTP response from a vulnerable or compromised back-end HTTP agent (e.g., server). See CanPrecede relationships for possible consequences.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-273 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-273 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-273`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey network to identify target] The adversary performs network reconnaissance by monitoring relevant traffic to identify the network path and parsing of the HTTP messages with the goal of identifying potential targets. | techniques: Scan networks to fingerprint HTTP infrastructure and monitor HTTP traffic to identify HTTP network path with a tool such as a Network Protocol A…
- Step 1 (Experiment): [Identify vulnerabilities in targeted HTTP infrastructure and technologies] The adversary sends a variety of benign/ambiguous HTTP requests to observe responses from HTTP infrastructure to intended targets in order to identify differences/discrepancies in the interpretation and parsing of HTTP requests by examining supported HTTP protocol versions, message sizes, and HTTP hea…
- Step 2 (Experiment): [Cause differential HTTP responses by experimenting with identified HTTP Response vulnerabilities] The adversary sends maliciously crafted HTTP request to back-end HTTP infrastructure to inject adversary data into HTTP responses (intended for intermediary and/or front-end client/victim HTTP agents communicating with back-end HTTP infrastructure) for the purpose of interfering…
- Step 1 (Exploit): [Perform HTTP Response Smuggling attack] Using knowledge discovered in the experiment section above, smuggle a message to cause one of the consequences. | techniques: Leverage techniques identified in the Experiment Phase.

## Prerequisites

- A vulnerable or compromised server or domain/site capable of allowing adversary to insert/inject malicious content that will appear in the server's response to target HTTP agents (e.g., proxies and users' web browsers).
- Differences in the way the two HTTP agents parse and interpret HTTP responses and its headers.
- HTTP agents running on HTTP/1.1 that allow for Keep Alive mode, Pipelined queries, and Chunked queries and responses.

## Skills required

- Medium: Detailed knowledge on HTTP protocol: request and response messages structure and usage of specific headers.
- Medium: Detailed knowledge on how specific HTTP agents receive, send, process, interpret, and parse a variety of HTTP messages and headers.
- Medium: Possess knowledge on the exact details in the discrepancies between several targeted HTTP agents in path of an HTTP message in parsing its message structure and individual headers.

## Resources required

- Tools capable of monitoring HTTP messages, and crafting malicious HTTP messages and/or injecting malicious content into HTTP messages.

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

- When using Undertow, a Java-based web server in Red Hat's Jboss Enterprise Application Platform version 7.0, the code responsible for parsing HTTP requests permitted invalid characters, that could allow the injection of data into HTTP responses from Undertow to clients when used in tandem with a proxy; allowing for web-cache poisoning, XSS, and confidentiality violation of sensitive information f…
- Mozilla Firefox and Thunderbird before 1.5.04, with various proxy servers, interpreted HTTP responses differently if HTTP response headers included a space between the header name and colon or if HTTP 1.1 headers were sent through a proxy configured with HTTP 1.0, allowing for HTTP Smuggling vulnerability. See also: CVE-2006-2786

## Related CAPECs (test these too)

- ChildOf → [CAPEC-220](CAPEC-220.md)
- PeerOf → [CAPEC-33](CAPEC-33.md)
- CanPrecede → [CAPEC-115](CAPEC-115.md)
- CanPrecede → [CAPEC-141](CAPEC-141.md)
- CanPrecede → [CAPEC-63](CAPEC-63.md)
- CanPrecede → [CAPEC-593](CAPEC-593.md)
- CanPrecede → [CAPEC-148](CAPEC-148.md)
- CanPrecede → [CAPEC-154](CAPEC-154.md)

## Related CWEs (run the cwe skill)

- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-436](../cwe/references/CWE-436.md) — run that CWE procedure after this CAPEC flow
- [CWE-444](../cwe/references/CWE-444.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-273 and CWE IDs
