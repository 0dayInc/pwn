# CAPEC-102: Session Sidejacking

- Catalog: [CAPEC-102](https://capec.mitre.org/data/definitions/102.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

Session sidejacking takes advantage of an unencrypted communication channel between a victim and target system. The attacker sniffs traffic on a network looking for session tokens in unencrypted traffic. Once a session token is captured, the attacker performs malicious actions by using the stolen token with the targeted application to impersonate the victim. This attack is a specific method of session hijacking, which is exploiting a valid session token to gain unauthorized access to a target system or information. Other methods to perform a session hijacking are session fixation, cross-site scripting, or compromising a user or server machine and stealing the session token.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-102 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser, PWN::Plugins::Zaproxy; PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-102 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-102`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Detect Unprotected Session Token Transfer] The attacker sniffs on the wireless network to detect unencrypted traffic that contains session tokens. | techniques: The attacker uses a network sniffer tool like ferret or hamster to monitor the wireless traffic at a WiFi hotspot while examining it for evidence of transmittal of session tokens in unencrypted or recognizably encrypted…
- Step 2 (Experiment): [Capture session token] The attacker uses sniffing tools to capture a session token from traffic.
- Step 3 (Experiment): [Insert captured session token] The attacker attempts to insert a captured session token into communication with the targeted application to confirm viability for exploitation.
- Step 4 (Exploit): [Session Token Exploitation] The attacker leverages the captured session token to interact with the targeted application in a malicious fashion, impersonating the victim.

## Prerequisites

- An attacker and the victim are both using the same WiFi network.
- The victim has an active session with a target system.
- The victim is not using a secure channel to communicate with the target system (e.g. SSL, VPN, etc.)
- The victim initiated communication with a target system that requires transfer of the session token or the target application uses AJAX and thereby periodically "rings home" asynchronously using the session token

## Skills required

- Low: Easy to use tools exist to automate this attack.

## Resources required

- A packet sniffing tool, such as wireshark, can be used to capture session information.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Integrity: Modify Data
- Confidentiality: Read Data
- Availability: Unreliable Execution

## Mitigations to bypass

- Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel.
- Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

## Example instances (payload / topology hints)

- The attacker and the victim are using the same WiFi public hotspot. When the victim connects to the hotspot, they has a hosted e-mail account open. This e-mail account uses AJAX on the client side which periodically asynchronously connects to the server side and transfers, amongst other things, the user's session token to the server. The communication is supposed to happen over HTTPS. However, th…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-593](CAPEC-593.md)

## Related CWEs (run the cwe skill)

- [CWE-294](../cwe/references/CWE-294.md) — run that CWE procedure after this CAPEC flow
- [CWE-522](../cwe/references/CWE-522.md) — run that CWE procedure after this CAPEC flow
- [CWE-523](../cwe/references/CWE-523.md) — run that CWE procedure after this CAPEC flow
- [CWE-319](../cwe/references/CWE-319.md) — run that CWE procedure after this CAPEC flow
- [CWE-614](../cwe/references/CWE-614.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-102 and CWE IDs
