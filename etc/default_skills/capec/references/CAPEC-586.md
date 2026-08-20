# CAPEC-586: Object Injection

- Catalog: [CAPEC-586](https://capec.mitre.org/data/definitions/586.html)
- Abstraction: Meta · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary attempts to exploit an application by injecting additional, malicious content during its processing of serialized objects. Developers leverage serialization in order to convert data or state into a static, binary format for saving to disk or transferring over a network. These objects are then deserialized when needed to recover the data/state. By injecting a malformed object into a vulnerable application, an adversary can potentially compromise the application by manipulating the deserialization process. This can result in a number of unwanted outcomes, including remote code execution.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-586 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST Java deserial / Eval modules, PWN::Plugins::Fuzz

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-586 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-586`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The target application must unserialize data before validation.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Availability: Resource Consumption — If a function is making an assumption on when to terminate, based on a sentry in a string, it could easily never terminate and exhaust available resources.
- Integrity: Modify Data — Attackers can modify objects or data that was assumed to be safe from modification.
- Authorization: Execute Unauthorized Commands — Functions that assume information in the deserialized object is valid could be exploited.

## Mitigations to bypass

- Implementation: Validate object before deserialization process
- Design: Limit which types can be deserialized.
- Implementation: Avoid having unnecessary types or gadgets available that can be leveraged for malicious ends. Use an allowlist of acceptable classes.
- Implementation: Keep session state on the server, when possible.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- [CWE-502](../cwe/references/CWE-502.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-586 and CWE IDs
