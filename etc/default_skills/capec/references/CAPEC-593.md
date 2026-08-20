# CAPEC-593: Session Hijacking

- Catalog: [CAPEC-593](https://capec.mitre.org/data/definitions/593.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

This type of attack involves an adversary that exploits weaknesses in an application's use of sessions in performing authentication. The adversary is able to steal or manipulate an active session and use it to gain unathorized access to the application.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-593 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-593 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-593`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Discover Existing Session Token] Through varrying means, an adversary will discover and store an existing session token for some other authenticated user session.
- Step 2 (Experiment): [Insert Found Session Token] The attacker attempts to insert a found session token into communication with the targeted application to confirm viability for exploitation.
- Step 3 (Exploit): [Session Token Exploitation] The attacker leverages the captured session token to interact with the targeted application in a malicious fashion, impersonating the victim.

## Prerequisites

- An application that leverages sessions to perform authentication.

## Skills required

- Low: Exploiting a poorly protected identity token is a well understood attack with many helpful resources available.

## Resources required

- The adversary must have the ability to communicate with the application over the network.

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Gain Privileges — A successful attack can enable an adversary to gain unauthorized access to an application.

## Mitigations to bypass

- Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity…

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-21](CAPEC-21.md)

## Related CWEs (run the cwe skill)

- [CWE-287](../cwe/references/CWE-287.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-593 and CWE IDs
