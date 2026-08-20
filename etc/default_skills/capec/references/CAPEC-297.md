# CAPEC-297: TCP ACK Ping

- Catalog: [CAPEC-297](https://capec.mitre.org/data/definitions/297.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: not stated · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

An adversary sends a TCP segment with the ACK flag set to a remote host for the purpose of determining if the host is alive. This is one of several TCP 'ping' types. The RFC 793 expected behavior for a service is to respond with a RST 'reset' packet to any unsolicited ACK segment that is not part of an existing connection. So by sending an ACK segment to a port, the adversary can identify that the host is alive by looking for a RST packet. Typically, a remote server will respond with a RST regardless of whether a port is open or closed. In this way, TCP ACK pings cannot discover the state of a remote port because the behavior is the same in either case. The firewall will look up the ACK packet in its state-table and discard the segment because it does not correspond to any active connection. A TCP ACK Ping can be used to discover if a host is alive via RST response packets sent from the host.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-297 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-297 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-297`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The ability to send an ACK packet to a remote host and identify the response. Creating the ACK packet without building a full connection requires the use of raw sockets. As a result, it is not possible to send a TCP ACK ping from some systems (Windows XP SP 2) without the use of third-party packet drivers like Winpcap. On other systems (BSD, Linux) administrative privileges are required in order…
- The target must employ a stateless firewall that lacks a rule set that rejects unsolicited ACK packets.
- The adversary requires the ability to craft custom TCP ACK segments for use during network reconnaissance. Sending an ACK ping requires the ability to access "raw sockets" in order to create the packets with direct access to the packet header.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- ACK scanning can be performed via the use of a port scanner or by raw socket manipulation using a scripting or programming language. Packet injection tools are also useful for this purpose. Depending upon the technique used it may also be necessary to sniff the network in order to see the response.

## Oracles (consequences)

- Confidentiality: Other
- Confidentiality, Access Control, Authorization: Bypass Protection Mechanism, Hide Activities

## Mitigations to bypass

- Leverage stateful firewalls that allow for the rejection of a packet that is not part of an existing connection.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-292](CAPEC-292.md)

## Related CWEs (run the cwe skill)

- [CWE-200](../cwe/references/CWE-200.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-297 and CWE IDs
