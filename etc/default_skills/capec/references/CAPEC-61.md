# CAPEC-61: Session Fixation

- Catalog: [CAPEC-61](https://capec.mitre.org/data/definitions/61.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

The attacker induces a client to establish a session with the target software using a session identifier provided by the attacker. Once the user successfully authenticates to the target software, the attacker uses the (now privileged) session identifier in their own transactions. This attack leverages the fact that the target software either relies on client-generated session identifiers or maintains the same session identifiers after privilege elevation.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-61 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-61 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-61`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Setup the Attack] Setup a session: The attacker has to setup a trap session that provides a valid session identifier, or select an arbitrary identifier, depending on the mechanism employed by the application. A trap session is a dummy session established with the application by the attacker and is used solely for the purpose of obtaining valid session identifiers. The attacker…
- Step 2 (Experiment): [Attract a Victim] Fixate the session: The attacker now needs to transfer the session identifier from the trap session to the victim by introducing the session identifier into the victim's browser. This is known as fixating the session. The session identifier can be introduced into the victim's browser by leveraging cross site scripting vulnerability, using META tags or setti…
- Step 3 (Exploit): [Abuse the Victim's Session] Takeover the fixated session: Once the victim has achieved a higher level of privilege, possibly by logging into the application, the attacker can now take over the session using the fixated session identifier. | techniques: The attacker loads the predefined session ID into their browser and browses to protected data or functionality.; The attacker l…

## Prerequisites

- Session identifiers that remain unchanged when the privilege levels change.
- Permissive session management mechanism that accepts random user-generated session identifiers
- Predictable session identifiers

## Skills required

- Low: Only basic skills are required to determine and fixate session identifiers in a user's browser. Subsequent attacks may require greater skill levels depending on the attackers' motives.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Use a strict session management mechanism that only accepts locally generated session identifiers: This prevents attackers from fixating session identifiers of their own choice.
- Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.
- Use session identifiers that are difficult to guess or brute-force: One way for the attackers to obtain valid session identifiers is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.

## Example instances (payload / topology hints)

- Consider a banking application that issues a session identifier in the URL to a user before login, and uses the same identifier to identify the customer following successful authentication. An attacker can easily leverage session fixation to access a victim's account by having the victim click on a forged link that contains a valid session identifier from a trapped session setup by the attacker.…
- An attacker can hijack user sessions, bypass authentication controls and possibly gain administrative privilege by fixating the session of a user authenticating to the Management Console on certain versions of Macromedia JRun 4.0. This can be achieved by setting the session identifier in the user's browser and having the user authenticate to the Management Console. Session fixation is possible si…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-593](CAPEC-593.md)

## Related CWEs (run the cwe skill)

- [CWE-384](../cwe/references/CWE-384.md) — run that CWE procedure after this CAPEC flow
- [CWE-664](../cwe/references/CWE-664.md) — run that CWE procedure after this CAPEC flow
- [CWE-732](../cwe/references/CWE-732.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-61 and CWE IDs
