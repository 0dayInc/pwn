# CAPEC-21: Exploitation of Trusted Identifiers

- Catalog: [CAPEC-21](https://capec.mitre.org/data/definitions/21.html)
- Abstraction: Meta · Status: Stable
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary guesses, obtains, or "rides" a trusted identifier (e.g. session ID, resource ID, cookie, etc.) to perform authorized actions under the guise of an authenticated user or service.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-21 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-21 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-21`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the application for Indicators of Susceptibility] Using a variety of methods, until one is found that applies to the target, the adversary probes for cookies, session tokens, or entry points that bypass identifiers altogether. | techniques: Spider all available pages; Attack known bad interfaces; Search outward-facing configuration and properties files for identifiers.
- Step 2 (Experiment): [Fetch samples] The adversary fetches many samples of identifiers. This may be through legitimate access (logging in, legitimate connections, etc.) or via systematic probing. | techniques: An adversary makes many anonymous connections and records the session IDs assigned.; An adversary makes authorized connections and records the session tokens or credentials issued.; An adve…
- Step 3 (Exploit): [Impersonate] An adversary can use successful experiments or authentications to impersonate an authorized user or system or to laterally move within a system or application
- Step 4 (Exploit): [Spoofing] Malicious data can be injected into the target system or into a victim user's system by an adversary. The adversary can also pose as a legitimate user to perform social engineering attacks.
- Step 5 (Exploit): [Data Exfiltration] The adversary can obtain sensitive data contained within the system or application.

## Prerequisites

- Server software must rely on weak identifier proof and/or verification schemes.
- Identifiers must have long lifetimes and potential for reusability.
- Server software must allow concurrent sessions to exist.

## Skills required

- Low: To achieve a direct connection with the weak or non-existent server session access control, and pose as an authorized user

## Resources required

- Ability to deploy software on network.
- Ability to communicate synchronously or asynchronously with server.

## Oracles (consequences)

- Confidentiality, Access Control, Authentication: Gain Privileges
- Confidentiality: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.
- Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.
- Implementation: If the identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.
- Implementation: If the web or application server supports it, then encrypting and/or signing the identifier (such as cookie) can protect the ID if intercepted.
- Design: Use strong session identifiers that are protected in transit and at rest.
- Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.
- Implementation: Verify authenticity of all identifiers at runtime.

## Example instances (payload / topology hints)

- Thin client applications like web applications are particularly vulnerable to session ID attacks. Since the server has very little control over the client, but still must track sessions, data, and objects on the server side, cookies and other mechanisms have been used to pass the key to the session data between the client and server. When these session keys are compromised it is trivial for an ad…
- For example, in a message queuing system that allows service requesters to post messages to its queue through an open channel (such as anonymous FTP), authorization is done through checking group or role membership contained in the posted message. However, there is no proof that the message itself, the information in the message (such group or role membership), or the process that wrote the messa…

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- [CWE-290](../cwe/references/CWE-290.md) — run that CWE procedure after this CAPEC flow
- [CWE-302](../cwe/references/CWE-302.md) — run that CWE procedure after this CAPEC flow
- [CWE-346](../cwe/references/CWE-346.md) — run that CWE procedure after this CAPEC flow
- [CWE-539](../cwe/references/CWE-539.md) — run that CWE procedure after this CAPEC flow
- [CWE-6](../cwe/references/CWE-6.md) — run that CWE procedure after this CAPEC flow
- [CWE-384](../cwe/references/CWE-384.md) — run that CWE procedure after this CAPEC flow
- [CWE-664](../cwe/references/CWE-664.md) — run that CWE procedure after this CAPEC flow
- [CWE-602](../cwe/references/CWE-602.md) — run that CWE procedure after this CAPEC flow
- [CWE-642](../cwe/references/CWE-642.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-21 and CWE IDs
