# CAPEC-28: Fuzzing

- Catalog: [CAPEC-28](https://capec.mitre.org/data/definitions/28.html)
- Abstraction: Meta · Status: Draft
- Likelihood of attack: High · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

In this attack pattern, the adversary leverages fuzzing to try to identify weaknesses in the system. Fuzzing is a software security and functionality testing method that feeds randomly constructed input to the system and looks for an indication that a failure in response to that input has occurred. Fuzzing treats the system as a black box and is totally free from any preconceptions or assumptions about the system. Fuzzing can help an attacker discover certain assumptions made about user input in the system. Fuzzing gives an attacker a quick way of potentially uncovering some of these assumptions despite not necessarily knowing anything about the internals of the system. These assumptions can then be turned against the system by specially crafting user input that may allow an attacker to achieve their goals.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-28 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-28 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-28`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Observe communication and inputs] The fuzzing attacker observes the target system looking for inputs and communications between modules, subsystems, or systems. | techniques: Network sniffing. Using a network sniffer such as wireshark, the attacker observes communications into and out of the target system.; Monitor API execution. Using a tool such as ktrace, strace, APISpy, or…
- Step 2 (Experiment): [Generate fuzzed inputs] Given a fuzzing tool, a target input or protocol, and limits on time, complexity, and input variety, generate a list of inputs to try. Although fuzzing is random, it is not exhaustive. Parameters like length, composition, and how many variations to try are important to get the most cost-effective impact from the fuzzer. | techniques: Boundary cases. G…
- Step 3 (Experiment): [Observe the outcome] Observe the outputs to the inputs fed into the system by fuzzers and see if anything interesting happens. If failure occurs, determine why that happened. Figure out the underlying assumption that was invalidated by the input.
- Step 4 (Exploit): [Craft exploit payloads] Put specially crafted input into the system that leverages the weakness identified through fuzzing and allows to achieve the goals of the attacker. Fuzzers often reveal ways to slip through the input validation filters and introduce unwanted data into the system. | techniques: Identify and embed shell code for the target system.; Embed higher level attac…

## Prerequisites

- (none listed in CAPEC catalog)

## Skills required

- Low: There is a wide variety of fuzzing tools available.

## Resources required

- Fuzzing tools.

## Oracles (consequences)

- Integrity: Modify Data
- Availability: Unreliable Execution
- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Integrity, Availability: Alter Execution Logic

## Mitigations to bypass

- Test to ensure that the software behaves as per specification and that there are no unintended side effects. Ensure that no assumptions about the validity of data are made.
- Use fuzz testing during the software QA process to uncover any surprises, uncover any assumptions or unexpected behavior.

## Example instances (payload / topology hints)

- A fuzz test reveals that when data length for a particular field exceeds certain length, the input validation filter fails and lets the user data in unfiltered. This provides an attacker with an injection vector to deliver the malicious payload into the system.

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-28 and CWE IDs
