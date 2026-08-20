# CAPEC-2: Inducing Account Lockout

- Catalog: [CAPEC-2](https://capec.mitre.org/data/definitions/2.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An attacker leverages the security functionality of the system aimed at thwarting potential attacks to launch a denial of service attack against a legitimate system user. Many systems, for instance, implement a password throttling mechanism that locks an account after a certain number of incorrect log in attempts. An attacker can leverage this throttling mechanism to lock a legitimate user out of their own account. The weakness that is being leveraged by an attacker is the very security feature that has been put in place to counteract attacks.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-2 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-2 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-2`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Experiment): [Investigate account lockout behavior of system] Investigate the security features present in the system that may trigger an account lockout | techniques: Analyze system documentation to find list of events that could potentially cause account lockout; Obtain user account in system and attempt to lock it out by sending malformed or incorrect data repeatedly; Determine another…
- Step 2 (Experiment): [Obtain list of user accounts to lock out] Generate a list of valid user accounts to lock out | techniques: Obtain list of authorized users using another attack pattern, such as SQL Injection.; Attempt to create accounts if possible; system should indicate if a user ID is already taken.; Attempt to brute force user IDs if system reveals whether a given user ID is valid or not…
- Step 3 (Exploit): [Lock Out Accounts] Perform lockout procedure for all accounts that the attacker wants to lock out. | techniques: For each user ID to be locked out, perform the lockout procedure discovered in the first step.

## Prerequisites

- The system has a lockout mechanism.
- An attacker must be able to reproduce behavior that would result in an account being locked.

## Skills required

- Low: No programming skills or computer knowledge is needed. An attacker can easily use this attack pattern following the Execution Flow above.

## Resources required

- Computer with access to the login portion of the target system

## Oracles (consequences)

- Availability: Resource Consumption — Denial of Service

## Mitigations to bypass

- Implement intelligent password throttling mechanisms such as those which take IP address into account, in addition to the login name.
- When implementing security features, consider how they can be misused and made to turn on themselves.

## Example instances (payload / topology hints)

- A famous example of this type an attack is the eBay attack. eBay always displays the user id of the highest bidder. In the final minutes of the auction, one of the bidders could try to log in as the highest bidder three times. After three incorrect log in attempts, eBay password throttling would kick in and lock out the highest bidder's account for some time. An attacker could then make their own…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-212](CAPEC-212.md)

## Related CWEs (run the cwe skill)

- [CWE-645](../cwe/references/CWE-645.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-2 and CWE IDs
