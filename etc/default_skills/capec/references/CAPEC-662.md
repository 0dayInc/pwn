# CAPEC-662: Adversary in the Browser (AiTB)

- Catalog: [CAPEC-662](https://capec.mitre.org/data/definitions/662.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits security vulnerabilities or inherent functionalities of a web browser, in order to manipulate traffic between two endpoints.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-662 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-662 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-662`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Experiment): The adversary tricks the victim into installing the Trojan Horse malware onto their system. | techniques: Conduct phishing attacks, drive-by malware installations, or masquerade malicious browser extensions as being legitimate.
- Step 2 (Experiment): The adversary inserts themself into the communication channel initially acting as a routing proxy between the two targeted components.
- Step 3 (Exploit): The adversary observes, filters, or alters passed data of their choosing to gain access to sensitive information or to manipulate the actions of the two target components for their own purposes.

## Prerequisites

- The adversary must install or convince a user to install a Trojan.
- There are two components communicating with each other.
- An attacker is able to identify the nature and mechanism of communication between the two target components.
- Strong mutual authentication is not used between the two target components yielding opportunity for adversarial interposition.
- For browser pivoting, the SeDebugPrivilege and a high-integrity process must both exist to execute this attack.

## Skills required

- Medium: Tricking the victim into installing the Trojan is often the most difficult aspect of this attack. Afterwards, the remainder of this attack is fairly trivial.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data

## Mitigations to bypass

- Ensure software and applications are only downloaded from legitimate and reputable sources, in addition to conducting integrity checks on the downloaded component.
- Leverage anti-malware tools, which can detect Trojan Horse malware.
- Use strong, out-of-band mutual authentication to always fully authenticate both ends of any communications channel.
- Limit user permissions to prevent browser pivoting.
- Ensure browser sessions are regularly terminated and when their effective lifetime ends.

## Example instances (payload / topology hints)

- An adversary conducts a phishing attack and tricks a victim into installing a malicious browser plugin. The adversary then positions themself between the victim and their banking institution. The victim begins by initiating a funds transfer from their personal savings to their personal checking account. Using injected JavaScript, the adversary captures this request and modifies it to transfer an…
- In 2020, the Agent Tesla malware was leveraged to conduct AiTB attacks against organizations within the gas, oil, and other energy sectors. The malware was delivered via a spearphishing campaign and has the capability to form-grab, keylog, copy clipboard data, extract credentials, and capture screenshots. [REF-630]
- Boy in the browser attacks are a subset of AiTB attacks. Similar to AiTB attacks, the adversary must first trick the victim into installing a Trojan, either via social engineering or drive-by-download attacks. The malware then modifies the victim's "hosts" file in order to reroute web traffic from an intended website to an adversary-controlled website that mimics the legitimate website. The adver…
- Man in the Mobile attacks are a subset of AiTB attacks that target mobile device users. Like AiTB attacks, an adversary convinces a victim to install a Trojan mobile application on their mobile device, often under the guise of security. Once the victim has installed the application, the adversary can capture all SMS traffic to bypass SMS-based out-of-band authentication systems. [REF-632]

## Related CAPECs (test these too)

- ChildOf → [CAPEC-94](CAPEC-94.md)

## Related CWEs (run the cwe skill)

- [CWE-300](../cwe/references/CWE-300.md) — run that CWE procedure after this CAPEC flow
- [CWE-494](../cwe/references/CWE-494.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-662 and CWE IDs
