# CAPEC-94: Adversary in the Middle (AiTM)

- Catalog: [CAPEC-94](https://capec.mitre.org/data/definitions/94.html)
- Abstraction: Meta · Status: Stable
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary targets the communication between two components (typically client and server), in order to alter or obtain data from transactions. A general approach entails the adversary placing themself within the communication channel between the two components.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-94 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-94 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-94`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine Communication Mechanism] The adversary determines the nature and mechanism of communication between two components, looking for opportunities to exploit. | techniques: Perform a sniffing attack and observe communication to determine a communication protocol.; Look for application documentation that might describe a communication mechanism used by a target.
- Step 2 (Experiment): [Position In Between Targets] The adversary inserts themself into the communication channel initially acting as a routing proxy between the two targeted components. | techniques: Install spyware on a client that will intercept outgoing packets and route them to their destination as well as route incoming packets back to the client.; Exploit a weakness in an encrypted communic…
- Step 3 (Exploit): [Use Intercepted Data Maliciously] The adversary observes, filters, or alters passed data of its choosing to gain access to sensitive information or to manipulate the actions of the two target components for their own purposes. | techniques: Prevent some messages from reaching their destination, causing a denial of service.

## Prerequisites

- There are two components communicating with each other.
- An attacker is able to identify the nature and mechanism of communication between the two target components.
- An attacker can eavesdrop on the communication between the target components.
- Strong mutual authentication is not used between the two target components yielding opportunity for attacker interposition.
- The communication occurs in clear (not encrypted) or with insufficient and spoofable encryption.

## Skills required

- Medium: This attack can get sophisticated since the attack may use cryptography.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data

## Mitigations to bypass

- Ensure Public Keys are signed by a Certificate Authority
- Encrypt communications using cryptography (e.g., SSL/TLS)
- Use Strong mutual authentication to always fully authenticate both ends of any communications channel.
- Exchange public keys using a secure channel

## Example instances (payload / topology hints)

- In 2017, security researcher Jerry Decime discovered that Equifax mobile applications were not leveraging HTTPS in all areas. Although authentication was properly utilizing HTTPS, in addition to validating the root of trust of the server certificate, other areas of the application were using HTTP to communicate. Adversaries could then conduct MITM attacks on rogue WiFi or cellular networks and hi…

## Related CAPECs (test these too)

- CanPrecede → [CAPEC-151](CAPEC-151.md)
- CanPrecede → [CAPEC-668](CAPEC-668.md)

## Related CWEs (run the cwe skill)

- [CWE-300](../cwe/references/CWE-300.md) — run that CWE procedure after this CAPEC flow
- [CWE-290](../cwe/references/CWE-290.md) — run that CWE procedure after this CAPEC flow
- [CWE-593](../cwe/references/CWE-593.md) — run that CWE procedure after this CAPEC flow
- [CWE-287](../cwe/references/CWE-287.md) — run that CWE procedure after this CAPEC flow
- [CWE-294](../cwe/references/CWE-294.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-94 and CWE IDs
