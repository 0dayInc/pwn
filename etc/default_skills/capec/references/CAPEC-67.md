# CAPEC-67: String Format Overflow in syslog()

- Catalog: [CAPEC-67](https://capec.mitre.org/data/definitions/67.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

This attack targets applications and software that uses the syslog() function insecurely. If an application does not explicitely use a format string parameter in a call to syslog(), user input can be placed in the format string parameter leading to a format string injection attack. Adversaries can then inject malicious format string commands into the function call leading to a buffer overflow. There are many reported software vulnerabilities with the root cause being a misuse of the syslog() function.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-67 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST BannedFunctionCallsC / UseAfterFree, PWN::Plugins::Assembly

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-67 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-67`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target application] The adversary identifies a target application or program to perform the buffer overflow on. In this attack, adversaries look for applications that use syslog() incorrectly.
- Step 2 (Experiment): [Find injection vector] The adversary identifies an injection vector to deliver the excessive content to the targeted application's buffer. For each user-controllable input that the adversary suspects is vulnerable to format string injection, attempt to inject formatting characters such as %n, %s, etc.. The goal is to manipulate the string creation using these formatting char…
- Step 3 (Experiment): [Craft overflow content] The adversary crafts the content to be injected. If the intent is to simply cause the software to crash, the content need only consist of an excessive quantity of random data. If the intent is to leverage the overflow for execution of arbitrary code, the adversary will craft a set of content that not only overflows the targeted buffer but does so in s…
- Step 4 (Exploit): [Overflow the buffer] Using the injection vector, the adversary supplies the program with the crafted format string injection, causing a buffer.

## Prerequisites

- The Syslog function is used without specifying a format string argument, allowing user input to be placed direct into the function call as a format string.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Availability: Unreliable Execution
- Confidentiality, Access Control, Authorization: Gain Privileges
- Integrity: Modify Data

## Mitigations to bypass

- The code should be reviewed for misuse of the Syslog function call. Manual or automated code review can be used. The reviewer needs to ensure that all format string functions are passed a static string which cannot be controlled by the user and that the proper number of arguments are always sent to that function as well. If at all possible, do not use the %n operator in format strings. The follow…

## Example instances (payload / topology hints)

- Format string vulnerability in TraceEvent function for ntop before 2.1 allows remote adversaries to execute arbitrary code by causing format strings to be injected into calls to the syslog function, via (1) an HTTP GET request, (2) a user name in HTTP authentication, or (3) a password in HTTP authentication. See also: CVE-2002-0412

## Related CAPECs (test these too)

- ChildOf → [CAPEC-100](CAPEC-100.md)
- ChildOf → [CAPEC-135](CAPEC-135.md)

## Related CWEs (run the cwe skill)

- [CWE-120](../cwe/references/CWE-120.md) — run that CWE procedure after this CAPEC flow
- [CWE-134](../cwe/references/CWE-134.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-680](../cwe/references/CWE-680.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-67 and CWE IDs
