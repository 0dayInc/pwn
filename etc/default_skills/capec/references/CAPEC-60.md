# CAPEC-60: Reusing Session IDs (aka Session Replay)

- Catalog: [CAPEC-60](https://capec.mitre.org/data/definitions/60.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack targets the reuse of valid session ID to spoof the target system in order to gain privileges. The attacker tries to reuse a stolen session ID used previously during a transaction to perform spoofing and session hijacking. Another name for this type of attack is Session Replay.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-60 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-60 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-60`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): The attacker interacts with the target host and finds that session IDs are used to authenticate users.
- Step 2 (Explore): The attacker steals a session ID from a valid user.
- Step 3 (Exploit): The attacker tries to use the stolen session ID to gain access to the system with the privileges of the session ID's original owner.

## Prerequisites

- The target host uses session IDs to keep track of the users.
- Session IDs are used to control access to resources.
- The session IDs used by the target host are not well protected from session theft.

## Skills required

- Low: If an attacker can steal a valid session ID, they can then try to be authenticated with that stolen session ID.
- Medium: More sophisticated attack can be used to hijack a valid session from a user and spoof a legitimate user by reusing their valid session ID.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Always invalidate a session ID after the user logout.
- Setup a session time out for the session IDs.
- Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate adversary in the middle attacks (CAPEC-94).
- Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.
- Encrypt the session data associated with the session ID.
- Use multifactor authentication.

## Example instances (payload / topology hints)

- OpenSSL and SSLeay allow remote attackers to reuse SSL sessions and bypass access controls. See also: CVE-1999-0428
- Merak Mail IceWarp Web Mail uses a static identifier as a user session ID that does not change across sessions, which could allow remote attackers with access to the ID to gain privileges as that user, e.g. by extracting the ID from the user's answer or forward URLs. See also: CVE-2002-0258

## Related CAPECs (test these too)

- ChildOf → [CAPEC-593](CAPEC-593.md)

## Related CWEs (run the cwe skill)

- [CWE-294](../cwe/references/CWE-294.md) — run that CWE procedure after this CAPEC flow
- [CWE-290](../cwe/references/CWE-290.md) — run that CWE procedure after this CAPEC flow
- [CWE-346](../cwe/references/CWE-346.md) — run that CWE procedure after this CAPEC flow
- [CWE-384](../cwe/references/CWE-384.md) — run that CWE procedure after this CAPEC flow
- [CWE-488](../cwe/references/CWE-488.md) — run that CWE procedure after this CAPEC flow
- [CWE-539](../cwe/references/CWE-539.md) — run that CWE procedure after this CAPEC flow
- [CWE-200](../cwe/references/CWE-200.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-664](../cwe/references/CWE-664.md) — run that CWE procedure after this CAPEC flow
- [CWE-732](../cwe/references/CWE-732.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-60 and CWE IDs
