# CAPEC-701: Browser in the Middle (BiTM)

- Catalog: [CAPEC-701](https://capec.mitre.org/data/definitions/701.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits the inherent functionalities of a web browser, in order to establish an unnoticed remote desktop connection in the victim's browser to the adversary's system. The adversary must deploy a web client with a remote desktop session that the victim can access.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-701 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-701 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-701`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify potential targets] The adversary identifies an application or service that the target is likely to use. | techniques: The adversary stands up a server to host the transparent browser and entices victims to use it by using a domain name similar to the legitimate application. In addition to the transparent browser, the adversary could al…
- Step 2 (Experiment): [Lure victims] The adversary crafts a phishing campaign to lure unsuspecting victims into using the transparent browser. | techniques: An adversary can create a convincing email with a link to download the web client and interact with the transparent browser.
- Step 3 (Exploit): [Monitor and Manipulate Data] When the victim establishes the connection to the transparent browser, the adversary can view victim activity and make alterations to what the victim sees when browsing the web. | techniques: Once a victim has established a connection to the transparent browser, the adversary can use installed tools such as a web proxy, keylogger, or additional mali…

## Prerequisites

- The adversary must create a convincing web client to establish the connection. The victim then needs to be lured onto the adversary's webpage. In addition, the victim's machine must not use local authentication APIs, a hardware token, or a Trusted Platform Module (TPM) to authenticate.

## Skills required

- Medium

## Resources required

- A web application with a client is needed to enable the victim's browser to establish a remote desktop connection to the system of the adversary.

## Oracles (consequences)

- Confidentiality, Access Control, Authentication: Gain Privileges
- Confidentiality, Authorization: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Implementation: Use strong, mutual authentication to fully authenticate with both ends of any communications channel

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-94](CAPEC-94.md)
- CanPrecede → [CAPEC-151](CAPEC-151.md)
- CanPrecede → [CAPEC-148](CAPEC-148.md)
- CanFollow → [CAPEC-98](CAPEC-98.md)

## Related CWEs (run the cwe skill)

- [CWE-294](../cwe/references/CWE-294.md) — run that CWE procedure after this CAPEC flow
- [CWE-345](../cwe/references/CWE-345.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-701 and CWE IDs
