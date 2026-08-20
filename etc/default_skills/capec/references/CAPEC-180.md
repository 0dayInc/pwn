# CAPEC-180: Exploiting Incorrectly Configured Access Control Security Levels

- Catalog: [CAPEC-180](https://capec.mitre.org/data/definitions/180.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An attacker exploits a weakness in the configuration of access controls and is able to bypass the intended protection that these measures guard against and thereby obtain unauthorized access to the system or network. Sensitive functionality should always be protected with access controls. However configuring all but the most trivial access control systems can be very complicated and there are many opportunities for mistakes. If an attacker can learn of incorrectly configured access security settings, they may be able to exploit this in an attack.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-180 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-180 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-180`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey] The attacker surveys the target application, possibly as a valid and authenticated user. | techniques: Spider the web site for all available links.; Brute force to guess all function names/action with different privileges.
- Step 2 (Experiment): [Identify weak points in access control configurations] The attacker probes the access control for functions and data identified in the Explore phase to identify potential weaknesses in how the access controls are configured. | techniques: The attacker attempts authenticated access to targeted functions and data.; The attacker attempts unauthenticated access to targeted funct…
- Step 3 (Exploit): [Access the function or data bypassing the access control] The attacker executes the function or accesses the data identified in the Explore phase bypassing the access control. | techniques: The attacker executes the function or accesses the data not authorized to them.

## Prerequisites

- The target must apply access controls, but incorrectly configure them. However, not all incorrect configurations can be exploited by an attacker. If the incorrect configuration applies too little security to some functionality, then the attacker may be able to exploit it if the access control would be the only thing preventing an attacker's access and it no longer does so. If the incorrect config…

## Skills required

- Low: In order to discover unrestricted resources, the attacker does not need special tools or skills. They only have to observe the resources or access mechanisms invoked as each action is performed and then try and access those access mechanisms directly.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Authorization: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism
- Availability: Unreliable Execution

## Mitigations to bypass

- Design: Configure the access control correctly.

## Example instances (payload / topology hints)

- For example, an incorrectly configured Web server, may allow unauthorized access to it, thus threaten the security of the Web application.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-122](CAPEC-122.md)
- CanPrecede → [CAPEC-17](CAPEC-17.md)

## Related CWEs (run the cwe skill)

- [CWE-732](../cwe/references/CWE-732.md) — run that CWE procedure after this CAPEC flow
- [CWE-1190](../cwe/references/CWE-1190.md) — run that CWE procedure after this CAPEC flow
- [CWE-1191](../cwe/references/CWE-1191.md) — run that CWE procedure after this CAPEC flow
- [CWE-1193](../cwe/references/CWE-1193.md) — run that CWE procedure after this CAPEC flow
- [CWE-1220](../cwe/references/CWE-1220.md) — run that CWE procedure after this CAPEC flow
- [CWE-1268](../cwe/references/CWE-1268.md) — run that CWE procedure after this CAPEC flow
- [CWE-1280](../cwe/references/CWE-1280.md) — run that CWE procedure after this CAPEC flow
- [CWE-1297](../cwe/references/CWE-1297.md) — run that CWE procedure after this CAPEC flow
- [CWE-1311](../cwe/references/CWE-1311.md) — run that CWE procedure after this CAPEC flow
- [CWE-1315](../cwe/references/CWE-1315.md) — run that CWE procedure after this CAPEC flow
- [CWE-1318](../cwe/references/CWE-1318.md) — run that CWE procedure after this CAPEC flow
- [CWE-1320](../cwe/references/CWE-1320.md) — run that CWE procedure after this CAPEC flow
- [CWE-1321](../cwe/references/CWE-1321.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-180 and CWE IDs
