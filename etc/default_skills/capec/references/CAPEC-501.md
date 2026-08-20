# CAPEC-501: Android Activity Hijack

- Catalog: [CAPEC-501](https://capec.mitre.org/data/definitions/501.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary intercepts an implicit intent sent to launch a Android-based trusted activity and instead launches a counterfeit activity in its place. The malicious activity is then used to mimic the trusted activity's user interface and prompt the target to enter sensitive data as if they were interacting with the trusted activity.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-501 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-501 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-501`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find an android application that uses implicit intents] Since this attack only works on android applications that use implicit intents, rather than explicit intents, an adversary must first identify an app that uses implicit intents to launch an Android-based trusted activity, and what that activity is.
- Step 2 (Experiment): [Create a malicious app] The adversary must create a malicious android app meant to intercept implicit intents to launch an Adroid-based trusted activity. This malicious app will mimic the trusted activiy's user interface to get the user to enter sensitive data. | techniques: Specify the type of intent wished to be intercepted in the malicious app's manifest file using an int…
- Step 3 (Experiment): [Get user to download malicious app] The adversary must get a user using the targeted app to download the malicious app by any means necessary
- Step 4 (Exploit): [Gather sensitive data through malicious app] Once the target application sends an implicit intent to launch a trusted activity, the malicious app will be launched instead that looks identical to the interface of that activity. When the user enters sensitive information it will be captured by the malicious app. | techniques: Gather login information from a user using a malicious…

## Prerequisites

- The adversary must have previously installed the malicious application onto the Android device that will run in place of the trusted activity.

## Skills required

- High: The adversary must typically overcome network and host defenses in order to place malware on the system.

## Resources required

- Malware capable of acting on the adversary's objectives.

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- To mitigate this type of an attack, explicit intents should be used whenever sensitive data is being sent. An 'explicit intent' is delivered to a specific application as declared within the intent, whereas an 'implicit intent' is directed to an application as defined by the Android operating system. If an implicit intent must be used, then it should be assumed that the intent will be received by…
- Never use implicit intents for inter-application communication.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-499](CAPEC-499.md)
- ChildOf → [CAPEC-173](CAPEC-173.md)

## Related CWEs (run the cwe skill)

- [CWE-923](../cwe/references/CWE-923.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-501 and CWE IDs
