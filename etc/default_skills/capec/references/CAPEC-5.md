# CAPEC-5: Blue Boxing


**Deprecated/Obsolete in CAPEC catalog.** Still execute the flow if the target exhibits it; prefer ChildOf/CanFollow replacements.

- Catalog: [CAPEC-5](https://capec.mitre.org/data/definitions/5.html)
- Abstraction: Detailed · Status: Obsolete
- Likelihood of attack: Medium · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

This type of attack against older telephone switches and trunks has been around for decades. A tone is sent by an adversary to impersonate a supervisor signal which has the effect of rerouting or usurping command of the line. While the US infrastructure proper may not contain widespread vulnerabilities to this type of attack, many companies are connected globally through call centers and business process outsourcing. These international systems may be operated in countries which have not upgraded Telco infrastructure and so are vulnerable to Blue boxing. Blue boxing is a result of failure on the part of the system to enforce strong authorization for administrative functions. While the infrastructure is different than standard current applications like web applications, there are historical lessons to be learned to upgrade the access control for administrative functions. This attack pattern is included in CAPEC for historical purposes.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-5 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-5 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-5`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- System must use weak authentication mechanisms for administrative functions.

## Skills required

- Low: Given a vulnerable phone system, the attackers' technical vector relies on attacks that are well documented in cracker 'zines and have been around for decades.

## Resources required

- CCITT-5 or other vulnerable lines, with the ability to send tones such as combined 2,400 Hz and 2,600 Hz tones to the switch

## Oracles (consequences)

- Availability: Resource Consumption — Denial of Service
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Implementation: Upgrade phone lines. Note this may be prohibitively expensive
- Use strong access control such as two factor access control for administrative access to the switch

## Example instances (payload / topology hints)

- An adversary identifies a vulnerable CCITT-5 phone line, and sends a combination tone to the switch in order to request administrative access. Based on tone and timing parameters the request is verified for access to the switch. Once the adversary has gained control of the switch launching calls, routing calls, and a whole host of opportunities are available.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-220](CAPEC-220.md)

## Related CWEs (run the cwe skill)

- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-5 and CWE IDs
