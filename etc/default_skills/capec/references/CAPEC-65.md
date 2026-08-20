# CAPEC-65: Sniff Application Code

- Catalog: [CAPEC-65](https://capec.mitre.org/data/definitions/65.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary passively sniffs network communications and captures application code bound for an authorized client. Once obtained, they can use it as-is, or through reverse-engineering glean sensitive information or exploit the trust relationship between the client and server. Such code may belong to a dynamic update to the client, a patch being applied to a client component or any such interaction where the client is authorized to communicate with the server.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-65 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-65 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-65`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Set up a sniffer] The adversary sets up a sniffer in the path between the server and the client and watches the traffic. | techniques: The adversary sets up a sniffer in the path between the server and the client.
- Step 2 (Exploit): [Capturing Application Code Bound During Patching]adversary knows that the computer/OS/application can request new applications to install, or it periodically checks for an available update. The adversary loads the sniffer set up during Explore phase, and extracts the application code from subsequent communication. The adversary then proceeds to reverse engineer the captured cod…

## Prerequisites

- The attacker must have the ability to place themself in the communication path between the client and server.
- The targeted application must receive some application code from the server; for example, dynamic updates, patches, applets or scripts.
- The attacker must be able to employ a sniffer on the network without being detected.

## Skills required

- Medium: The attacker needs to setup a sniffer for a sufficient period of time so as to capture meaningful quantities of code. The presence of the sniffer should not be detected on the network. Also if the attacker plans to employ an adversary-in-the-middle attack (CAPEC-94), the client or server must not r…

## Resources required

- The Attacker needs the ability to capture communications between the client being updated and the server providing the update. In the case that encryption obscures client/server communication the attacker will either need to lift key material from the client.

## Oracles (consequences)

- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Design: Encrypt all communication between the client and server.
- Implementation: Use SSL, SSH, SCP.
- Operation: Use "ifconfig/ipconfig" or other tools to detect the sniffer installed in the network.

## Example instances (payload / topology hints)

- Attacker receives notification that the computer/OS/application has an available update, loads a network sniffing tool, and extracts update data from subsequent communication. The attacker then proceeds to reverse engineer the captured stream to gain sensitive information, such as encryption keys, validation algorithms, applications patches, etc..
- Plain code, such as applets or JavaScript, is also part of the executing application. If such code is transmitted unprotected, the attacker can capture the code and possibly reverse engineer it to gain sensitive information, such as encryption keys, validation algorithms and such.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-157](CAPEC-157.md)
- CanPrecede → [CAPEC-37](CAPEC-37.md)

## Related CWEs (run the cwe skill)

- [CWE-319](../cwe/references/CWE-319.md) — run that CWE procedure after this CAPEC flow
- [CWE-311](../cwe/references/CWE-311.md) — run that CWE procedure after this CAPEC flow
- [CWE-318](../cwe/references/CWE-318.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-65 and CWE IDs
