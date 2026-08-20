# CAPEC-95: WSDL Scanning

- Catalog: [CAPEC-95](https://capec.mitre.org/data/definitions/95.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack targets the WSDL interface made available by a web service. The attacker may scan the WSDL interface to reveal sensitive information about invocation patterns, underlying technology implementations and associated vulnerabilities. This type of probing is carried out to perform more serious attacks (e.g. parameter tampering, malicious content injection, command injection, etc.). WSDL files provide detailed information about the services ports and bindings available to consumers. For instance, the attacker can submit special characters or malicious content to the Web service and can cause a denial of service condition or illegal access to database records. In addition, the attacker may try to guess other private methods by using the information provided in the WSDL files.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-95 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST command-exec modules, PWN::Plugins::PS

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-95 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-95`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Scan for WSDL Documents] The adversary scans for WSDL documents. The WDSL document written in XML is like a handbook on how to communicate with the web services provided by the target host. It provides an open view of the application (function details, purpose, functional break down, entry points, message types, etc.). This is very useful information for the adversary.
- Step 2 (Experiment): [Analyze WSDL files] An adversary will analyze the WSDL files and try to find potential weaknesses by sending messages matching the pattern described in the WSDL file. The adversary could run through all of the operations with different message request patterns until a breach is identified.
- Step 3 (Exploit): [Craft malicious content] Once an adversary finds a potential weakness, they can craft malicious content to be sent to the system. For instance the adversary may try to submit special characters and observe how the system reacts to an invalid request. The message sent by the adversary may not be XML validated and cause unexpected behavior.

## Prerequisites

- A client program connecting to a web service can read the WSDL to determine what functions are available on the server.
- The target host exposes vulnerable functions within its WSDL interface.

## Skills required

- Low: This attack can be as simple as reading WSDL and starting sending invalid request.
- Medium: This attack can be used to perform more sophisticated attacks (SQL injection, etc.)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- It is important to protect WSDL file or provide limited access to it.
- Review the functions exposed by the WSDL interface (especially if you have used a tool to generate it). Make sure that none of them is vulnerable to injection.
- Ensure the WSDL does not expose functions and APIs that were not intended to be exposed.
- Pay attention to the function naming convention (within the WSDL interface). Easy to guess function name may be an entry point for attack.
- Validate the received messages against the WSDL Schema. Incomplete solution.

## Example instances (payload / topology hints)

- A WSDL interface may expose a function vulnerable to SQL Injection.
- The Web Services Description Language (WSDL) allows a web service to advertise its capabilities by describing operations and parameters needed to access the service. As discussed in step 5 of this series, WSDL is often generated automatically, using utilities such as Java2WSDL, which takes a class or interface and builds a WSDL file in which interface methods are exposed as web services. Because…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-54](CAPEC-54.md)

## Related CWEs (run the cwe skill)

- [CWE-538](../cwe/references/CWE-538.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-95 and CWE IDs
