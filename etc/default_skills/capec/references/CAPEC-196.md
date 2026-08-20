# CAPEC-196: Session Credential Falsification through Forging

- Catalog: [CAPEC-196](https://capec.mitre.org/data/definitions/196.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An attacker creates a false but functional session credential in order to gain or usurp access to a service. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. If an attacker is able to forge valid session credentials they may be able to bypass authentication or piggy-back off some other authenticated user's session. This attack differs from Reuse of Session IDs and Session Sidejacking attacks in that in the latter attacks an attacker uses a previous or existing credential without modification while, in a forging attack, the attacker must create their own credential, although it may be based on previously observed credentials.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-196 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-196 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-196`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Analyze and Understand Session IDs] The attacker finds that the targeted application use session credentials to identify legitimate users. | techniques: An attacker makes many anonymous connections and records the session IDs.; An attacker makes authorized connections and records the session tokens or credentials.
- Step 2 (Experiment): [Create Session IDs.] Attackers craft messages containing their forged credentials in GET, POST request, HTTP headers or cookies. | techniques: The attacker manipulates the HTTP request message and adds their forged session IDs in to the requests or cookies.
- Step 3 (Exploit): [Abuse the Victim's Session Credentials] The attacker fixates falsified session ID to the victim when victim access the system. Once the victim has achieved a higher level of privilege, possibly by logging into the application, the attacker can now take over the session using the forged session identifier. | techniques: The attacker loads the predefined or predicted session ID i…

## Prerequisites

- The targeted application must use session credentials to identify legitimate users. Session identifiers that remains unchanged when the privilege levels change. Predictable session identifiers.

## Skills required

- Medium: Forge the session credential and reply the request.

## Resources required

- Attackers may require tools to craft messages containing their forged credentials, and ability to send HTTP request to a web application.

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.
- Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

## Example instances (payload / topology hints)

- This example uses client side scripting to set session ID in the victim's browser. The JavaScript code document.cookie="sessionid=0123456789" fixates a falsified session credential into victim's browser, with the help of crafted a URL link. http://www.example.com/<script>document.cookie="sessionid=0123456789";</script> A similar example uses session ID as an argument of the URL. http://www.exampl…

## Related CAPECs (test these too)

- CanPrecede → [CAPEC-384](CAPEC-384.md)
- CanPrecede → [CAPEC-61](CAPEC-61.md)
- ChildOf → [CAPEC-21](CAPEC-21.md)

## Related CWEs (run the cwe skill)

- [CWE-384](../cwe/references/CWE-384.md) — run that CWE procedure after this CAPEC flow
- [CWE-664](../cwe/references/CWE-664.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-196 and CWE IDs
