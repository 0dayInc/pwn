# CAPEC-12: Choosing Message Identifier

- Catalog: [CAPEC-12](https://capec.mitre.org/data/definitions/12.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This pattern of attack is defined by the selection of messages distributed via multicast or public information channels that are intended for another client by determining the parameter value assigned to that client. This attack allows the adversary to gain access to potentially privileged information, and to possibly perpetrate other attacks through the distribution means by impersonation. If the channel/message being manipulated is an input rather than output mechanism for the system, (such as a command bus), this style of attack could be used to change the adversary's identifier to more a privileged one.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-12 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-12 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-12`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine Nature of Messages] Determine the nature of messages being transported as well as the identifiers to be used as part of the attack
- Step 2 (Experiment): [Authenticate] If required, authenticate to the distribution channel
- Step 3 (Experiment): [Identify Known Client Identifiers] If any particular client's information is available through a control channel available to all users, the adversary will discover particular identifiers for targeted clients by observing this channel, or requesting client information through this channel.
- Step 4 (Experiment): [Change Message Identifier] Adversaries with client access connecting to output channels could change their channel identifier and see someone else's (perhaps more privileged) data.

## Prerequisites

- Information and client-sensitive (and client-specific) data must be present through a distribution channel available to all users.
- Distribution means must code (through channel, message identifiers, or convention) message destination in a manner visible within the distribution means itself (such as a control channel) or in the messages themselves.

## Skills required

- Low: All the adversary needs to discover is the format of the messages on the channel/distribution means and the particular identifier used within the messages.

## Resources required

- The adversary needs the ability to control source code or application configuration responsible for selecting which message/channel id is absorbed from the public distribution means.

## Oracles (consequences)

- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Associate some ACL (in the form of a token) with an authenticated user which they provide middleware. The middleware uses this token as part of its channel/message selection for that client, or part of a discerning authorization decision for privileged channels/messages. The purpose is to architect the system in a way that associates proper authentication/authorization with each channel/message.
- Re-architect system input/output channels as appropriate to distribute self-protecting data. That is, encrypt (or otherwise protect) channels/messages so that only authorized readers can see them.

## Example instances (payload / topology hints)

- A certain B2B interface on a large application codes for messages passed over an MQSeries queue, on a single "Partners" channel. Messages on that channel code for their client destination based on a partner_ID field, held by each message. That field is a simple integer. Adversaries having access to that channel, perhaps a particularly nosey partner, can simply choose to store messages of another…

## Related CAPECs (test these too)

- PeerOf → [CAPEC-21](CAPEC-21.md)
- ChildOf → [CAPEC-216](CAPEC-216.md)

## Related CWEs (run the cwe skill)

- [CWE-201](../cwe/references/CWE-201.md) — run that CWE procedure after this CAPEC flow
- [CWE-306](../cwe/references/CWE-306.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-12 and CWE IDs
