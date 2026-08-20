# CAPEC-275: DNS Rebinding

- Catalog: [CAPEC-275](https://capec.mitre.org/data/definitions/275.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary serves content whose IP address is resolved by a DNS server that the adversary controls. After initial contact by a web browser (or similar client), the adversary changes the IP address to which its name resolves, to an address within the target organization that is not publicly accessible. This allows the web browser to examine this internal address on behalf of the adversary.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-275 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-275 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-275`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify potential DNS rebinding targets] An adversary publishes content on their own server with their own name and DNS server. Attract HTTP traffic and explore rebinding vulnerabilities in browsers, flash players of old version. | techniques: Adversary uses Web advertisements to attract the victim to access adversary's DNS. Explore the versions of web browser or flash players…
- Step 2 (Experiment): [Establish initial target access to adversary DNS] The first time the target accesses the adversary's content, the adversary's name must be resolved to an IP address. The adversary's DNS server performs this resolution, providing a short Time-To-Live (TTL) in order to prevent the target from caching the value.
- Step 3 (Experiment): [Rebind DNS resolution to target address] The target makes a subsequent request to the adversary's content and the adversary's DNS server must again be queried, but this time the DNS server returns an address internal to the target's organization that would not be accessible from an outside source.
- Step 4 (Experiment): [Determine exploitability of DNS rebinding access to target address] The adversary can then use scripts in the content the target retrieved from the adversary in the original message to exfiltrate data from the named internal addresses.
- Step 5 (Exploit): [Access & exfiltrate data within the victim's security zone] The adversary can then use scripts in the content the target retrieved from the adversary in the original message to exfiltrate data from the internal addresses. This allows adversaries to discover sensitive information about the internal network of an enterprise. | techniques: Adversary attempts to use victim's browse…

## Prerequisites

- The target browser must access content server from the adversary controlled DNS name. Web advertisements are often used for this purpose. The target browser must honor the TTL value returned by the adversary and re-resolve the adversary's DNS name after initial contact.

## Skills required

- Medium: Setup DNS server and the adversary's web server. Write a malicious script to allow the victim to connect to the web server.

## Resources required

- The adversary must serve some web content that a victim accesses initially. This content must include executable content that queries the adversary's DNS name (to provide the second DNS resolution) and then performs the follow-on attack against the internal system. The adversary also requires a customized DNS server that serves an IP address for their registered DNS name, but which resolves subse…

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Design: IP Pinning causes browsers to record the IP address to which a given name resolves and continue using this address regardless of the TTL set in the DNS response. Unfortunately, this is incompatible with the design of some legitimate sites.
- Implementation: Reject HTTP request with a malicious Host header.
- Implementation: Employ DNS resolvers that prevent external names from resolving to internal addresses.

## Example instances (payload / topology hints)

- The adversary registers a domain name, such as www.evil.com with IP address 1.3.5.7, delegates it to their own DNS server (1.3.5.2), and uses phishing links or emails to get HTTP traffic. Instead of sending a normal TTL record, the DNS server sends a very short TTL record (for example, 1 second), preventing DNS response of entry[www.evil.com, 1.3.5.7] from being cached on victim's (192.168.1.10)…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-194](CAPEC-194.md)

## Related CWEs (run the cwe skill)

- [CWE-350](../cwe/references/CWE-350.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-275 and CWE IDs
