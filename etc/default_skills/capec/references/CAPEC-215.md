# CAPEC-215: Fuzzing for application mapping

- Catalog: [CAPEC-215](https://capec.mitre.org/data/definitions/215.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

An attacker sends random, malformed, or otherwise unexpected messages to a target application and observes the application's log or error messages returned. The attacker does not initially know how a target will respond to individual messages but by attempting a large number of message variants they may find a variant that trigger's desired behavior. In this attack, the purpose of the fuzzing is to observe the application's log and error messages, although fuzzing a target can also sometimes cause the target to enter an unstable state, causing a crash.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-215 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-215 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-215`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Observe communication and inputs] The fuzzing adversary observes the target system looking for inputs and communications between modules, subsystems, or systems. | techniques: Network sniffing. Using a network sniffer such as wireshark, the adversary observes communications into and out of the target system.; Monitor API execution. Using a tool such as ktrace, strace, APISpy, o…
- Step 2 (Experiment): [Generate fuzzed inputs] Given a fuzzing tool, a target input or protocol, and limits on time, complexity, and input variety, generate a list of inputs to try. Although fuzzing is random, it is not exhaustive. Parameters like length, composition, and how many variations to try are important to get the most cost-effective impact from the fuzzer. | techniques: Boundary cases. G…
- Step 3 (Experiment): [Observe the outcome] Observe the outputs to the inputs fed into the system by fuzzers and see if there are any log or error messages that might provide information to map the application
- Step 4 (Exploit): [Craft exploit payloads] An adversary usually needs to modify the fuzzing parameters according to the observed error messages to get the desired sensitive information for the application. To defeat correlation, the adversary may try changing the origin IP addresses or client browser identification strings or start a new session from where they left off in obfuscating the attack.…

## Prerequisites

- The target application must fail to sanitize incoming messages adequately before processing.

## Skills required

- Medium: Although fuzzing parameters is not difficult, and often possible with automated fuzzing tools, interpreting the error conditions and modifying the parameters so as to move further in the process of mapping the application requires detailed knowledge of target platform, the languages and packages us…

## Resources required

- Fuzzing tools, which automatically generate and send message variants, are necessary for this attack. The attacker must have sufficient access to send messages to the target. The attacker must also have the ability to observe the target application's log and/or error messages in order to collect information about the target.

## Oracles (consequences)

- Confidentiality: Other — Information Leakage

## Mitigations to bypass

- Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to res…
- Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.
- Implementation: Obfuscate server fields of HTTP response.
- Implementation: Hide inner ordering of HTTP response header.
- Implementation: Customizing HTTP error codes such as 404 or 500.
- Implementation: Hide HTTP response header software information filed.
- Implementation: Hide cookie's software information filed.
- Implementation: Obfuscate database type in Database API's error message.

## Example instances (payload / topology hints)

- The following code generates an error message that leaks the full pathname of the configuration file. $ConfigDir = "/home/myprog/config"; $uname = GetUserInput("username"); ExitError("Bad hacker!") if ($uname !~ /^\w+$/); $file = "$ConfigDir/$uname.txt"; if (! (-e $file)) { ExitError("Error: $file does not exist"); } ... If this code is running on a server, such as a web application, then the per…
- In languages that utilize stack traces, revealing them can give adversaries information that allows them to map functions and file locations for an application. The following Java method prints out a stack trace that exposes the application to this attack pattern. public void httpGet(HttpServletRequest request, HttpServletResponse response) { try { processRequest(); } catch (Exception ex) { ex.pr…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-54](CAPEC-54.md)
- ChildOf → [CAPEC-28](CAPEC-28.md)

## Related CWEs (run the cwe skill)

- [CWE-209](../cwe/references/CWE-209.md) — run that CWE procedure after this CAPEC flow
- [CWE-532](../cwe/references/CWE-532.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-215 and CWE IDs
