# CAPEC-261: Fuzzing for garnering other adjacent user/sensitive data

- Catalog: [CAPEC-261](https://capec.mitre.org/data/definitions/261.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary who is authorized to send queries to a target sends variants of expected queries in the hope that these modified queries might return information (directly or indirectly through error logs) beyond what the expected set of queries should provide.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-261 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite; PWN::Plugins::Fuzz

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-261 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-261`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Observe communication and inputs] The fuzzing adversary observes the target system looking for inputs and communications between modules, subsystems, or systems. | techniques: Network sniffing. Using a network sniffer such as wireshark, the adversary observes communications into and out of the target system.; Monitor API execution. Using a tool such as ktrace, strace, APISpy, o…
- Step 2 (Experiment): [Generate fuzzed inputs] Given a fuzzing tool, a target input or protocol, and limits on time, complexity, and input variety, generate a list of inputs to try. Although fuzzing is random, it is not exhaustive. Parameters like length, composition, and how many variations to try are important to get the most cost-effective impact from the fuzzer. | techniques: Boundary cases. G…
- Step 3 (Experiment): [Observe the outcome] Observe the outputs to the inputs fed into the system by fuzzers and see if there are any log or error messages that either provide user/sensitive data or give information about an expected template that could be used to produce this data.
- Step 4 (Exploit): [Craft exploit payloads] If the logs did not reveal any user/sensitive data, an adversary will attempt to make the fuzzing inputs form to an expected template | techniques: Create variants of expected templates that request additional information; Create variants that exclude limiting clauses; Create variants that alter fields taht identify the requester in order to subvert acce…

## Prerequisites

- The server must assume that the queries it receives follow specific templates and/or have fields or attributes that follow specific procedures. The server must process queries that it receives without adequately checking or sanitizing queries to ensure they follow these templates.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- The attacker must have sufficient privileges to send queries to the targeted server. A normal client might limit the nature of these queries, so the attacker must either have a modified client or their own application which allows them to modify the expected queries.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- A client that queries an employee database might have templates such that the user only supplies the target's name and the template dictates the fields to be returned (location, position in the company, phone number, etc.). If the server does not verify that the query matches one of the expected templates, an attacker who is allowed to send normal queries could modify their query to try to return…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-54](CAPEC-54.md)

## Related CWEs (run the cwe skill)

- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-261 and CWE IDs
