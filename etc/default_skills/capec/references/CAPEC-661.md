# CAPEC-661: Root/Jailbreak Detection Evasion via Debugging

- Catalog: [CAPEC-661](https://capec.mitre.org/data/definitions/661.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary inserts a debugger into the program entry point of a mobile application to modify the application binary, with the goal of evading Root/Jailbreak detection. Mobile device users often Root/Jailbreak their devices in order to gain administrative control over the mobile operating system and/or to install third-party mobile applications that are not provided by authorized application stores (e.g. Google Play Store and Apple App Store). Rooting/Jailbreaking a mobile device also provides users with access to system debuggers and disassemblers, which can be leveraged to exploit applications by dumping the application's memory at runtime in order to remove or bypass signature verification methods. This further allows the adversary to evade Root/Jailbreak detection mechanisms, which can result in execution of administrative commands, obtaining confidential data, impersonating legitimate users of the application, and more.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-661 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-661 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-661`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify application with attack potential] The adversary searches for and identifies a mobile application that could be exploited for malicious purposes (e.g. banking, voting, or medical applications). | techniques: Search application stores for mobile applications worth exploiting
- Step 2 (Experiment): [Debug the target application] The adversary inserts the debugger into the program entry point of the mobile application, after the application's signature has been identified, to dump its memory contents. | techniques: Insert the debugger at the mobile application's program entry point, after the application's signature has been identified.; Dump the memory region containing…
- Step 3 (Experiment): [Remove application signature verification methods] Remove signature verification methods from the decrypted code and resign the application with a self-signed certificate.
- Step 4 (Exploit): [Execute the application and evade Root/Jailbreak detection methods] The application executes with the self-signed certificate, while believing it contains a trusted certificate. This now allows the adversary to evade Root/Jailbreak detection via code hooking or other methods. | techniques: Optional: Hook code into the target application.

## Prerequisites

- A debugger must be able to be inserted into the targeted application.

## Skills required

- High: Knowledge about Root/Jailbreak detection and evasion techniques.
- Medium: Knowledge about runtime debugging.

## Resources required

- The adversary must have a Rooted/Jailbroken mobile device with debugging capabilities.

## Oracles (consequences)

- Integrity, Authorization: Execute Unauthorized Commands — Through Root/Jailbreak Detection Evasion via Debugging, the adversary compromises the integrity of the application.
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Access Control: Read Data — An adversary may leverage Root/Jailbreak Detection Evasion via Debugging in order to obtain sensitive information.

## Mitigations to bypass

- Instantiate checks within the application code that ensures debuggers are not attached.

## Example instances (payload / topology hints)

- An adversary targets an iOS banking application in an attempt to compromise sensitive user data. The adversary launches the application with the iOS debugger and sets a breakpoint at the program entry point, after the application's signature has been verified. Next, the adversary dumps the memory region that contains the decrypted code from the address space of the binary. The 'Restrict' flag is…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-121](CAPEC-121.md)
- CanPrecede → [CAPEC-68](CAPEC-68.md)
- CanPrecede → [CAPEC-660](CAPEC-660.md)

## Related CWEs (run the cwe skill)

- [CWE-489](../cwe/references/CWE-489.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-661 and CWE IDs
