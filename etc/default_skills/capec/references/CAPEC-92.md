# CAPEC-92: Forced Integer Overflow

- Catalog: [CAPEC-92](https://capec.mitre.org/data/definitions/92.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack forces an integer variable to go out of range. The integer variable is often used as an offset such as size of memory allocation or similarly. The attacker would typically control the value of such variable and try to get it out of range. For instance the integer in question is incremented past the maximum possible value, it may wrap to become a very small, or negative number, therefore providing a very incorrect value which can lead to unexpected behavior. At worst the attacker can execute arbitrary code.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-92 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-92 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-92`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): The first step is exploratory meaning the attacker looks for an integer variable that they can control.
- Step 2 (Experiment): The attacker finds an integer variable that they can write into or manipulate and try to get the value of the integer out of the possible range.
- Step 3 (Exploit): The integer variable is forced to have a value out of range which set its final value to an unexpected value.
- Step 4 (Exploit): The target host acts on the data and unexpected behavior may happen.

## Prerequisites

- The attacker can manipulate the value of an integer variable utilized by the target host.
- The target host does not do proper range checking on the variable before utilizing it.
- When the integer variable is incremented or decremented to an out of range value, it gets a very different value (e.g. very small or negative number)

## Skills required

- Low: An attacker can simply overflow an integer by inserting an out of range value.
- High: Exploiting a buffer overflow by injecting malicious code into the stack of a software system or even the heap can require a higher skill level.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality: Read Data
- Availability: Unreliable Execution

## Mitigations to bypass

- Use a language or compiler that performs automatic bounds checking.
- Carefully review the service's implementation before making it available to user. For instance you can use manual or automated code review to uncover vulnerabilities such as integer overflow.
- Use an abstraction library to abstract away risky APIs. Not a complete solution.
- Always do bound checking before consuming user input data.

## Example instances (payload / topology hints)

- Integer overflow in the ProcAuWriteElement function in server/dia/audispatch.c in Network Audio System (NAS) before 1.8a SVN 237 allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a large max_samples value. See also: CVE-2007-1544
- The following code illustrates an integer overflow. The declaration of total integer as "unsigned short int" assumes that the length of the first and second arguments fits in such an integer [REF-547], [REF-548]. include <stdlib.h> include <string.h> include <stdio.h> int main (int argc, char *const *argv) { if (argc !=3){ printf("Usage: prog_name <string1> <string2>\n"); exit(-1); } unsigned sho…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-128](CAPEC-128.md)

## Related CWEs (run the cwe skill)

- [CWE-190](../cwe/references/CWE-190.md) — run that CWE procedure after this CAPEC flow
- [CWE-128](../cwe/references/CWE-128.md) — run that CWE procedure after this CAPEC flow
- [CWE-120](../cwe/references/CWE-120.md) — run that CWE procedure after this CAPEC flow
- [CWE-122](../cwe/references/CWE-122.md) — run that CWE procedure after this CAPEC flow
- [CWE-196](../cwe/references/CWE-196.md) — run that CWE procedure after this CAPEC flow
- [CWE-680](../cwe/references/CWE-680.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-92 and CWE IDs
