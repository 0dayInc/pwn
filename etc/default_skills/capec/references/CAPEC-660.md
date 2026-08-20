# CAPEC-660: Root/Jailbreak Detection Evasion via Hooking

- Catalog: [CAPEC-660](https://capec.mitre.org/data/definitions/660.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary forces a non-restricted mobile application to load arbitrary code or code files, via Hooking, with the goal of evading Root/Jailbreak detection. Mobile device users often Root/Jailbreak their devices in order to gain administrative control over the mobile operating system and/or to install third-party mobile applications that are not provided by authorized application stores (e.g. Google Play Store and Apple App Store). Adversaries may further leverage these capabilities to escalate privileges or bypass access control on legitimate applications. Although many mobile applications check if a mobile device is Rooted/Jailbroken prior to authorized use of the application, adversaries may be able to "hook" code in order to circumvent these checks. Successfully evading Root/Jailbreak detection allows an adversary to execute administrative commands, obtain confidential data, impersonate legitimate users of the application, and more.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-660 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-660 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-660`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify application with attack potential] The adversary searches for and identifies a mobile application that could be exploited for malicious purposes (e.g. banking, voting, or medical applications). | techniques: Search application stores for mobile applications worth exploiting
- Step 2 (Experiment): [Develop code to be hooked into chosen target application] The adversary develops code or leverages existing code that will be hooked into the target application in order to evade Root/Jailbreak detection methods. | techniques: Develop code or leverage existing code to bypass Root/Jailbreak detection methods.; Test the code to see if it works.; Iteratively develop the code un…
- Step 3 (Exploit): [Execute code hooking to evade Root/Jailbreak detection methods] Once hooking code has been developed or obtained, execute the code against the target application to evade Root/Jailbreak detection methods. | techniques: Hook code into the target application.

## Prerequisites

- The targeted application must be non-restricted to allow code hooking.

## Skills required

- High: Knowledge about Root/Jailbreak detection and evasion techniques.
- Medium: Knowledge about code hooking.

## Resources required

- The adversary must have a Rooted/Jailbroken mobile device.
- The adversary needs to have enough access to the target application to control the included code or file.

## Oracles (consequences)

- Integrity, Authorization: Execute Unauthorized Commands — Through Root/Jailbreak Detection Evasion via Hooking, the adversary compromises the integrity of the application.
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality, Access Control: Read Data — An adversary may leverage Root/Jailbreak Detection Evasion via Hooking in order to obtain sensitive information.

## Mitigations to bypass

- Ensure mobile applications are signed appropriately to avoid code inclusion via hooking.
- Inspect the application's memory for suspicious artifacts, such as shared objects/JARs or dylibs, after other Root/Jailbreak detection methods.
- Inspect the application's stack trace for suspicious method calls.
- Allow legitimate native methods, and check for non-allowed native methods during Root/Jailbreak detection methods.
- For iOS applications, ensure application methods do not originate from outside of Apple's SDK.

## Example instances (payload / topology hints)

- An adversary targets a non-restricted iOS banking application in an attempt to compromise sensitive user data. The adversary creates Objective-C runtime code that always returns "false" when checking for the existence of the Cydia application. The malicious code is then dynamically loaded into the application via the DYLD_INSERT_LIBRARIES environment variable. When the banking applications checks…
- An adversary targets a mobile voting application on an Android device with the goal of committing voter fraud. Leveraging the Xposed framework, the adversary is able to create and hook Java code into the application that bypasses Root detection methods. When the voting application attempts to detect a Rooted device by checking for commonly known installed packages associated with Rooting, the hoo…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-251](CAPEC-251.md)

## Related CWEs (run the cwe skill)

- [CWE-829](../cwe/references/CWE-829.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-660 and CWE IDs
