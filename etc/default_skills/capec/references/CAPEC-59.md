# CAPEC-59: Session Credential Falsification through Prediction

- Catalog: [CAPEC-59](https://capec.mitre.org/data/definitions/59.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack targets predictable session ID in order to gain privileges. The attacker can predict the session ID used during a transaction to perform spoofing and session hijacking.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-59 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell; PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-59 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-59`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find Session IDs] The attacker interacts with the target host and finds that session IDs are used to authenticate users. | techniques: An attacker makes many anonymous connections and records the session IDs assigned.; An attacker makes authorized connections and records the session tokens or credentials issued.
- Step 2 (Explore): [Characterize IDs] The attacker studies the characteristics of the session ID (size, format, etc.). As a results the attacker finds that legitimate session IDs are predictable. | techniques: Cryptanalysis. The attacker uses cryptanalysis to determine if the session IDs contain any cryptographic protections.; Pattern tests. The attacker looks for patterns (odd/even, repetition, m…
- Step 3 (Experiment): [Match issued IDs] The attacker brute forces different values of session ID and manages to predict a valid session ID. | techniques: The attacker models the session ID algorithm enough to produce a compatible session IDs, or just one match.
- Step 4 (Exploit): [Use matched Session ID] The attacker uses the falsified session ID to access the target system. | techniques: The attacker loads the session ID into their web browser and browses to restricted data or functionality.; The attacker loads the session ID into their network communications and impersonates a legitimate user to gain access to data or functionality.

## Prerequisites

- The target host uses session IDs to keep track of the users.
- Session IDs are used to control access to resources.
- The session IDs used by the target host are predictable. For example, the session IDs are generated using predictable information (e.g., time).

## Skills required

- Low: There are tools to brute force session ID. Those tools require a low level of knowledge.
- Medium: Predicting Session ID may require more computation work which uses advanced analysis such as statistical analysis.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Use a strong source of randomness to generate a session ID.
- Use adequate length session IDs
- Do not use information available to the user in order to generate session ID (e.g., time).
- Ideas for creating random numbers are offered by Eastlake [RFC1750]
- Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

## Example instances (payload / topology hints)

- Jetty before 4.2.27, 5.1 before 5.1.12, 6.0 before 6.0.2, and 6.1 before 6.1.0pre3 generates predictable session identifiers using java.util.random, which makes it easier for remote attackers to guess a session identifier through brute force attacks, bypass authentication requirements, and possibly conduct cross-site request forgery attacks. See also: CVE-2006-6969
- mod_usertrack in Apache 1.3.11 through 1.3.20 generates session ID's using predictable information including host IP address, system time and server process ID, which allows local users to obtain session ID's and bypass authentication when these session ID's are used for authentication. See also: CVE-2001-1534

## Related CAPECs (test these too)

- ChildOf → [CAPEC-196](CAPEC-196.md)

## Related CWEs (run the cwe skill)

- [CWE-290](../cwe/references/CWE-290.md) — run that CWE procedure after this CAPEC flow
- [CWE-330](../cwe/references/CWE-330.md) — run that CWE procedure after this CAPEC flow
- [CWE-331](../cwe/references/CWE-331.md) — run that CWE procedure after this CAPEC flow
- [CWE-346](../cwe/references/CWE-346.md) — run that CWE procedure after this CAPEC flow
- [CWE-488](../cwe/references/CWE-488.md) — run that CWE procedure after this CAPEC flow
- [CWE-539](../cwe/references/CWE-539.md) — run that CWE procedure after this CAPEC flow
- [CWE-200](../cwe/references/CWE-200.md) — run that CWE procedure after this CAPEC flow
- [CWE-6](../cwe/references/CWE-6.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-384](../cwe/references/CWE-384.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-59 and CWE IDs
