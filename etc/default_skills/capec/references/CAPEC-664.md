# CAPEC-664: Server Side Request Forgery

- Catalog: [CAPEC-664](https://capec.mitre.org/data/definitions/664.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits improper input validation by submitting maliciously crafted input to a target application running on a server, with the goal of forcing the server to make a request either to itself, to web services running in the server’s internal network, or to external third parties. If successful, the adversary’s request will be made with the server’s privilege level, bypassing its authentication controls. This ultimately allows the adversary to access sensitive data, execute commands on the server’s network, and make external requests with the stolen identity of the server. Server Side Request Forgery attacks differ from Cross Site Request Forgery attacks in that they target the server itself, whereas CSRF attacks exploit an insecure user authentication mechanism to perform unauthorized actions on the user's behalf.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-664 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::TransparentBrowser, PWN::Plugins::BurpSuite, PWN::Plugins::Sock; PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite; PWN::SDR, extro_rf_tune

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-664 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-664`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find target application] Find target web application that accepts a user input and retrieves data from the server
- Step 2 (Experiment): [Examine existing application requests] Examine HTTP/GET requests to view the URL query format. Adversaries test to see if this type of attack is possible through weaknesses in an application's protection to Server Side Request Forgery | techniques: Attempt manipulating the URL to retrieve an error response/code from the server to determine if URL/request validation is done.;…
- Step 3 (Exploit): [Malicious request] Adversary crafts a malicious URL request that assumes the privilege level of the server to query internal or external network services and sends the request to the application

## Prerequisites

- Server must be running a web application that processes HTTP requests.

## Skills required

- Medium: The adversary will have to detect the vulnerability through an intermediary service or specify maliciously crafted URLs and analyze the server response.
- High: The adversary will be required to access internal resources, extract information, or leverage the services running on the server to perform unauthorized actions such as traversing the local network or routing a reflected TCP DDoS through them.

## Resources required

- [None] No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Integrity, Confidentiality, Availability: Modify Data
- Confidentiality: Read Data
- Availability: Resource Consumption

## Mitigations to bypass

- Handling incoming requests securely is the first line of action to mitigate this vulnerability. This can be done through URL validation.
- Further down the process flow, examining the response and verifying that it is as expected before sending would be another way to secure the server.
- Allowlist the DNS name or IP address of every service the web application is required to access is another effective security measure. This ensures the server cannot make external requests to arbitrary services.
- Requiring authentication for local services adds another layer of security between the adversary and internal services running on the server. By enforcing local authentication, an adversary will not gain access to all internal services only with access to the server.
- Enforce the usage of relevant URL schemas. By limiting requests be made only through HTTP or HTTPS, for example, attacks made through insecure schemas such as file://, ftp://, etc. can be prevented.

## Example instances (payload / topology hints)

- An e-commerce website allows a customer to filter results by specific categories. When the customer selects the category of choice, the web shop queries a back-end service to retrieve the requested products. The request may look something like: POST /product/category HTTP/1.0 Content-Type: application/x-www-form-urlencoded Content-Length: 200 vulnerableService=http://vulnerableshop.net:8080/produ…
- The CallStranger attack is an observed example of SSRF. It specifically targets the UPnP (Universal Plug and Play) protocol used by various network devices and gaming consoles. To execute the attack, an adversary performs a scan of the LAN to discover UPnP enabled devices, and subsequently a list of UPnP services they use. Once the UPnP service endpoints are listed, a vulnerability in the UPnP pr…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-115](CAPEC-115.md)

## Related CWEs (run the cwe skill)

- [CWE-918](../cwe/references/CWE-918.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-664 and CWE IDs
