# CAPEC-141: Cache Poisoning

- Catalog: [CAPEC-141](https://capec.mitre.org/data/definitions/141.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker exploits the functionality of cache technologies to cause specific data to be cached that aids the attackers' objectives. This describes any attack whereby an attacker places incorrect or harmful material in cache. The targeted cache can be an application's cache (e.g. a web browser cache) or a public cache (e.g. a DNS or ARP cache). Until the cache is refreshed, most applications or clients will treat the corrupted cache value as valid. This can lead to a wide range of exploits including redirecting web browsers towards sites that install malware and repeatedly incorrect calculations based on the incorrect value.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-141 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::TransparentBrowser, PWN::Plugins::URIScheme; PWN::Plugins::Packet, extro_packet, PWN::Plugins::Tor

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-141 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-141`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify and explore caches] Use tools to sniff traffic and scan a network in order to locate application's cache (e.g. a web browser cache) or a public cache (e.g. a DNS or ARP cache) that may have vulnerabilities. Look for poisoning point in cache table entries. | techniques: Run tools that check available entries in the cache.
- Step 2 (Experiment): [Cause specific data to be cached] An attacker sends bogus request to the target, and then floods responses that trick a cache to remember malicious responses, which are wrong answers of queries. | techniques: Intercept or modify a query, or send a bogus query with known credentials (such as transaction ID).
- Step 3 (Exploit): [Redirect users to malicious website] As the attacker succeeds in exploiting the vulnerability, they are able to manipulate and interpose malicious response data to targeted victim queries. | techniques: Intercept or modify a query, or send a bogus query with known credentials (such as transaction ID).; Adversary-in-the-Middle attacks (CAPEC-94) intercept secure communication be…

## Prerequisites

- The attacker must be able to modify the value stored in a cache to match a desired value.
- The targeted application must not be able to detect the illicit modification of the cache and must trust the cache value in its calculations.

## Skills required

- Medium: To overwrite/modify targeted cache

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Configuration: Disable client side caching.
- Implementation: Listens for query replies on a network, and sends a notification via email when an entry changes.

## Example instances (payload / topology hints)

- In this example, an attacker sends request to a local DNS server to look up www.example .com. The associated IP address of www.example.com is 1.3.5.7. Local DNS usually caches IP addresses and do not go to remote DNS every time. Since the local record is not found, DNS server tries to connect to remote DNS for queries. However, before the remote DNS returns the right IP address 1.3.5.7, the attac…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-161](CAPEC-161.md)

## Related CWEs (run the cwe skill)

- [CWE-348](../cwe/references/CWE-348.md) — run that CWE procedure after this CAPEC flow
- [CWE-345](../cwe/references/CWE-345.md) — run that CWE procedure after this CAPEC flow
- [CWE-349](../cwe/references/CWE-349.md) — run that CWE procedure after this CAPEC flow
- [CWE-346](../cwe/references/CWE-346.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-141 and CWE IDs
