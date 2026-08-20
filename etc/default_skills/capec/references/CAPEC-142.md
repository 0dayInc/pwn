# CAPEC-142: DNS Cache Poisoning

- Catalog: [CAPEC-142](https://capec.mitre.org/data/definitions/142.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

A domain name server translates a domain name (such as www.example.com) into an IP address that Internet hosts use to contact Internet resources. An adversary modifies a public DNS cache to cause certain names to resolve to incorrect addresses that the adversary specifies. The result is that client applications that rely upon the targeted cache for domain name resolution will be directed not to the actual address of the specified domain name but to some other address. Adversaries can use this to herd clients to sites that install malware on the victim's computer or to masquerade as part of a Pharming attack.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-142 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-142 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-142`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Explore resolver caches] Check DNS caches on local DNS server and client's browser with DNS cache enabled. | techniques: Run tools that check the resolver cache in the memory to see if it contains a target DNS entry.; Figure out if the client's browser has DNS cache enabled.
- Step 2 (Experiment): [Attempt sending crafted records to DNS cache] A request is sent to the authoritative server for target website and wait for the iterative name resolver. An adversary sends bogus request to the DNS local server, and then floods responses that trick a DNS cache to remember malicious responses, which are wrong answers of DNS query. | techniques: Adversary must know the transact…
- Step 3 (Exploit): [Redirect users to malicious website] As the adversary succeeds in exploiting the vulnerability, the victim connects to a malicious site using a good web site's domain name. | techniques: Redirecting Web traffic to a site that looks enough like the original so as to not raise any suspicion.; Adversary-in-the-Middle (CAPEC-94) intercepts secure communication between two parties.

## Prerequisites

- A DNS cache must be vulnerable to some attack that allows the adversary to replace addresses in its lookup table.Client applications must trust the corrupted cashed values and utilize them for their domain name resolutions.

## Skills required

- Medium: To overwrite/modify targeted DNS cache

## Resources required

- The adversary must have the resources to modify the targeted cache. In addition, in most cases the adversary will wish to host the sites to which users will be redirected, although in some cases redirecting to a third party site will accomplish the adversary's goals.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Configuration: Make sure your DNS servers have been updated to the latest versions
- Configuration: UNIX services like rlogin, rsh/rcp, xhost, and nfs are all susceptible to wrong information being held in a cache. Care should be taken with these services so they do not rely upon DNS caches that have been exposed to the Internet.
- Configuration: Disable client side DNS caching.

## Example instances (payload / topology hints)

- In this example, an adversary sends request to a local DNS server to look up www.example .com. The associated IP address of www.example.com is 1.3.5.7. Local DNS usually caches IP addresses and do not go to remote DNS every time. Since the local record is not found, DNS server tries to connect to remote DNS for queries. However, before the remote DNS returns the right IP address 1.3.5.7, the adve…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-141](CAPEC-141.md)
- CanPrecede → [CAPEC-89](CAPEC-89.md)

## Related CWEs (run the cwe skill)

- [CWE-348](../cwe/references/CWE-348.md) — run that CWE procedure after this CAPEC flow
- [CWE-345](../cwe/references/CWE-345.md) — run that CWE procedure after this CAPEC flow
- [CWE-349](../cwe/references/CWE-349.md) — run that CWE procedure after this CAPEC flow
- [CWE-346](../cwe/references/CWE-346.md) — run that CWE procedure after this CAPEC flow
- [CWE-350](../cwe/references/CWE-350.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-142 and CWE IDs
