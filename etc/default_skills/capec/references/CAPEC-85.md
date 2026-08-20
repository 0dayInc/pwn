# CAPEC-85: AJAX Footprinting

- Catalog: [CAPEC-85](https://capec.mitre.org/data/definitions/85.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

This attack utilizes the frequent client-server roundtrips in Ajax conversation to scan a system. While Ajax does not open up new vulnerabilities per se, it does optimize them from an attacker point of view. A common first step for an attacker is to footprint the target environment to understand what attacks will work. Since footprinting relies on enumeration, the conversational pattern of rapid, multiple requests and responses that are typical in Ajax applications enable an attacker to look for many vulnerabilities, well-known ports, network locations and so on. The knowledge gained through Ajax fingerprinting can be used to support other attacks, such as XSS.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-85 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::BurpSuite, PWN::Plugins::TransparentBrowser, PWN::Plugins::Zaproxy

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-85 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-85`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Send request to target webpage and analyze HTML] Using a browser or an automated tool, an adversary sends requests to a webpage and records the received HTML response. Adversaries then analyze the HTML to identify any known underlying JavaScript architectures. This can aid in mappiong publicly known vulnerabilities to the webpage and can also helpo the adversary guess applicati…

## Prerequisites

- The user must allow JavaScript to execute in their browser

## Skills required

- Medium: To land and launch a script on victim's machine with appropriate footprinting logic for enumerating services and vulnerabilities in JavaScript

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- Design: Use browser technologies that do not allow client side scripting.
- Implementation: Perform input validation for all remote content.

## Example instances (payload / topology hints)

- Footprinting can be executed over almost any protocol including HTTP, TCP, UDP, and ICMP, with the general goal of gaining further information about a host environment to launch further attacks. The attacker can probe the system for banners, vulnerabilities, filenames, available services, and in short anything the host process has access to. The results of the probe are either used to execute jav…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-580](CAPEC-580.md)
- CanPrecede → [CAPEC-63](CAPEC-63.md)

## Related CWEs (run the cwe skill)

- [CWE-79](../cwe/references/CWE-79.md) — run that CWE procedure after this CAPEC flow
- [CWE-113](../cwe/references/CWE-113.md) — run that CWE procedure after this CAPEC flow
- [CWE-348](../cwe/references/CWE-348.md) — run that CWE procedure after this CAPEC flow
- [CWE-96](../cwe/references/CWE-96.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-116](../cwe/references/CWE-116.md) — run that CWE procedure after this CAPEC flow
- [CWE-184](../cwe/references/CWE-184.md) — run that CWE procedure after this CAPEC flow
- [CWE-86](../cwe/references/CWE-86.md) — run that CWE procedure after this CAPEC flow
- [CWE-692](../cwe/references/CWE-692.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-85 and CWE IDs
