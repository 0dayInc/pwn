# CAPEC-634: Probe Audio and Video Peripherals

- Catalog: [CAPEC-634](https://capec.mitre.org/data/definitions/634.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

The adversary exploits the target system's audio and video functionalities through malware or scheduled tasks. The goal is to capture sensitive information about the target for financial, personal, political, or other gains which is accomplished by collecting communication data between two parties via the use of peripheral devices (e.g. microphones and webcams) or applications with audio and video capabilities (e.g. Skype) on a system.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-634 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-634 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-634`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- Knowledge of the target device's or application’s vulnerabilities that can be capitalized on with malicious code. The adversary must be able to place the malicious code on the target device.

## Skills required

- High: To deploy a hidden process or malware on the system to automatically collect audio and video data.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- Prevent unknown code from executing on a system through the use of an allowlist policy.
- Patch installed applications as soon as new updates become available.

## Example instances (payload / topology hints)

- An adversary can capture audio and video, and transmit the recordings to a C2 server or a similar capability.
- An adversary can capture and record from audio peripherals in a vehicle via a Car Whisperer attack. If an adversary is within close proximity to a vehicle with Bluetooth capabilities, they may attempt to connect to the hands-free system when it is in pairing mode. With successful authentication, if an authentication system is present at all, an adversary may be able to play music/voice recordings…
- An adversary may also use a technique called Bluebugging, which is similar to Bluesnarfing but requires the adversary to be between 10-15 meters of the target device. Bluebugging creates a backdoor for an attacker to listen/record phone calls, forward calls, send SMS and retrieve the phonebook.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-651](CAPEC-651.md)
- ChildOf → [CAPEC-545](CAPEC-545.md)

## Related CWEs (run the cwe skill)

- [CWE-267](../cwe/references/CWE-267.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-634 and CWE IDs
