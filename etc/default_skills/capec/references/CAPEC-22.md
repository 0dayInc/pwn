# CAPEC-22: Exploiting Trust in Client

- Catalog: [CAPEC-22](https://capec.mitre.org/data/definitions/22.html)
- Abstraction: Meta · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attack of this type exploits vulnerabilities in client/server communication channel authentication and data integrity. It leverages the implicit trust a server places in the client, or more importantly, that which the server believes is the client. An attacker executes this type of attack by communicating directly with the server where the server believes it is communicating only with a valid client. There are numerous variations of this type of attack.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-22 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-22 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-22`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- Server software must rely on client side formatted and validated values, and not reinforce these checks on the server side.

## Skills required

- Medium: The attacker must have fairly detailed knowledge of the syntax and semantics of client/server communications protocols and grammars

## Resources required

- Ability to communicate synchronously or asynchronously with server

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data

## Mitigations to bypass

- Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.
- Design: Do not rely on client validation or encoding for security purposes.
- Design: Utilize digital signatures to increase authentication assurance.
- Design: Utilize two factor authentication to increase authentication assurance.
- Implementation: Perform input validation for all remote content.

## Example instances (payload / topology hints)

- Web applications may use JavaScript to perform client side validation, request encoding/formatting, and other security functions, which provides some usability benefits and eliminates some client-server round-tripping. However, the web server cannot assume that the requests it receives have been subject to those validations, because an attacker can use an alternate method for crafting the HTTP Re…
- Web 2.0 style applications may be particularly vulnerable because they in large part rely on existing infrastructure which provides scalability without the ability to govern the clients. Attackers identify vulnerabilities that either assume the client side is responsible for some security services (without the requisite ability to ensure enforcement of these checks) and/or the lack of a hardened,…
- Many web applications use client side scripting like JavaScript to enforce authentication, authorization, session state and other variables, but at the end of day they all make requests to the server. These client side checks may provide usability and performance gains, but they lack integrity in terms of the http request. It is possible for an attacker to post variables directly to the server wi…
- Many message oriented middleware systems like MQ Series are rely on information that is passed along with the message request for making authorization decisions, for example what group or role the request should be passed. However, if the message server does not or cannot authenticate the authorization information in the request then the server's policy decisions about authorization are trivial t…

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- [CWE-290](../cwe/references/CWE-290.md) — run that CWE procedure after this CAPEC flow
- [CWE-287](../cwe/references/CWE-287.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-200](../cwe/references/CWE-200.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-22 and CWE IDs
