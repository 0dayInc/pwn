# CAPEC-74: Manipulating State

- Catalog: [CAPEC-74](https://capec.mitre.org/data/definitions/74.html)
- Abstraction: Meta · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

The adversary modifies state information maintained by the target software or causes a state transition in hardware. If successful, the target will use this tainted state and execute in an unintended manner. State management is an important function within a software application. User state maintained by the application can include usernames, payment information, browsing history as well as application-specific contents such as items in a shopping cart. Manipulating user state can be employed by an adversary to elevate privilege, conduct fraudulent transactions or otherwise modify the flow of the application to derive certain benefits. If there is a hardware logic error in a finite state machine, the adversary can use this to put the system in an undefined state which could cause a denial of service or exposure of secure data.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-74 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Serial, PWN::Plugins::BusPirate

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-74 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-74`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): Adversary determines the nature of state management employed by the target. This includes determining the location (client-side, server-side or both applications) and possibly the items stored as part of user state.
- Step 2 (Experiment): The adversary now tries to modify the user state contents (possibly indiscriminately if the contents are encrypted or otherwise obfuscated) or cause a state transition and observe the effects of this change on the target.
- Step 3 (Exploit): Having determined how to manipulate the state, the adversary can perform illegitimate actions.

## Prerequisites

- User state is maintained at least in some way in user-controllable locations, such as cookies or URL parameters.
- There is a faulty finite state machine in the hardware logic that can be exploited.

## Skills required

- Medium: The adversary needs to have knowledge of state management as employed by the target application, and also the ability to manipulate the state in a meaningful way.

## Resources required

- The adversary needs a data tampering tool capable of generating and creating custom inputs to aid in the attack, like Fiddler, Wireshark, or a similar in-browser plugin (e.g., Tamper Data for Firefox).

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Integrity: Modify Data
- Availability: Unreliable Execution

## Mitigations to bypass

- Do not rely solely on user-controllable locations, such as cookies or URL parameters, to maintain user state.
- Avoid sensitive information, such as usernames or authentication and authorization information, in user-controllable locations.
- Sensitive information that is part of the user state must be appropriately protected to ensure confidentiality and integrity at each request.
- All possible states must be handled by hardware finite state machines.

## Example instances (payload / topology hints)

- During the authentication process, an application stores the authentication decision (auth=0/1) in unencrypted cookies. At every request, this cookie is checked to permit or deny a request. An adversary can easily violate this representation of user state and set auth=1 at every request in order to gain illegitimate access and elevated privilege in the application.

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- [CWE-372](../cwe/references/CWE-372.md) — run that CWE procedure after this CAPEC flow
- [CWE-315](../cwe/references/CWE-315.md) — run that CWE procedure after this CAPEC flow
- [CWE-353](../cwe/references/CWE-353.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow
- [CWE-1245](../cwe/references/CWE-1245.md) — run that CWE procedure after this CAPEC flow
- [CWE-1253](../cwe/references/CWE-1253.md) — run that CWE procedure after this CAPEC flow
- [CWE-1265](../cwe/references/CWE-1265.md) — run that CWE procedure after this CAPEC flow
- [CWE-1271](../cwe/references/CWE-1271.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-74 and CWE IDs
