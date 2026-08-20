# CAPEC-170: Web Application Fingerprinting

- Catalog: [CAPEC-170](https://capec.mitre.org/data/definitions/170.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

An attacker sends a series of probes to a web application in order to elicit version-dependent and type-dependent behavior that assists in identifying the target. An attacker could learn information such as software versions, error pages, and response headers, variations in implementations of the HTTP protocol, directory structures, and other similar information about the targeted service. This information can then be used by an attacker to formulate a targeted attack plan. While web application fingerprinting is not intended to be damaging (although certain activities, such as network scans, can sometimes cause disruptions to vulnerable applications inadvertently) it may often pave the way for more damaging attacks.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-170 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-170 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-170`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Request fingerprinting] Use automated tools or send web server specific commands to web server and wait for server's response. | techniques: Use automated tools or send web server specific commands to web server and then receive server's response.
- Step 2 (Experiment): [Increase the accuracy of server fingerprinting of Web servers] Attacker usually needs to send several different commands to accurately identify the web server. Attacker can also use automated tools to send requests to the server. The responses of the server may be different in terms of protocol behavior. | techniques: Observe the ordering of the several HTTP response headers…
- Step 3 (Experiment): [Identify Web Application Software] After the web server platform software has been identified, the attacker start to identify web application technologies such as ASP, .NET, PHP and Java on the server. | techniques: Examine the file name extensions in URL, for example .php indicates PHP script interfaced with Apache server.; Examine the HTTP Response Headers. This may leak i…
- Step 4 (Experiment): [Identify Backend Database Version] Determining the database engine type can assist attackers' attempt to successfully execute SQL injection. Some database API such as ODBC will show a database type as part of the driver information when reporting an error. | techniques: Use tools to send bogus SQL query to the server and check error pages.

## Prerequisites

- Any web application can be fingerprinted. However, some configuration choices can limit the useful information an attacker may collect during a fingerprinting attack.

## Skills required

- Low: Attacker knows how to send HTTP request, SQL query to a web application.

## Resources required

- While simple fingerprinting can be accomplished with only a web browser, for more thorough fingerprinting an attacker requires a variety of tools to collect information about the target. These tools might include protocol analyzers, web-site crawlers, and fuzzing tools. Footprinting a service adequately may also take a few days if the attacker wishes the footprinting attempt to go undetected.

## Oracles (consequences)

- Confidentiality: Other — Information Leakage

## Mitigations to bypass

- Implementation: Obfuscate server fields of HTTP response.
- Implementation: Hide inner ordering of HTTP response header.
- Implementation: Customizing HTTP error codes such as 404 or 500.
- Implementation: Hide URL file extension.
- Implementation: Hide HTTP response header software information filed.
- Implementation: Hide cookie's software information filed.
- Implementation: Appropriately deal with error messages.
- Implementation: Obfuscate database type in Database API's error message.

## Example instances (payload / topology hints)

- An attacker sends malformed requests or requests of nonexistent pages to the server. Consider the following HTTP responses. Response from Apache 1.3.23 $ nc apache.server.com 80 GET / HTTP/3.0 HTTP/1.1 400 Bad Request Date: Sun, 15 Jun 2003 17:12: 37 GMT Server: Apache/1.3.23 Connection: close Transfer: chunked Content-Type: text/HTML; charset=iso-8859-1 Response from IIS 5.0 $ nc iis.server.com…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-541](CAPEC-541.md)

## Related CWEs (run the cwe skill)

- [CWE-497](../cwe/references/CWE-497.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-170 and CWE IDs
