# CAPEC-204: Lifting Sensitive Data Embedded in Cache

- Catalog: [CAPEC-204](https://capec.mitre.org/data/definitions/204.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary examines a target application's cache, or a browser cache, for sensitive information. Many applications that communicate with remote entities or which perform intensive calculations utilize caches to improve efficiency. However, if the application computes or receives sensitive information and the cache is not appropriately protected, an attacker can browse the cache and retrieve this information. This can result in the disclosure of sensitive information.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-204 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-204 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-204`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify Application Cache] An adversary first identifies an application that utilizes a cache. This could either be a web application storing data in a browser cache, or an application running on a separate machine. The adversary examines the cache to determine file permissions and possible encryption. | techniques: Use probing tools to look for application cache files on a ma…
- Step 2 (Experiment): [Attempt to Access Cache] Once the cache has been discovered, the adversary attempts to access the cached data. This often requires previous access to a machine hosting the target application. | techniques: Use priviledge escalation to access cache files that might have strict privileges.; If the application cache is encrypted with weak encryption, attempt to understand the e…
- Step 3 (Exploit): [Lift Sensitive Data from Cache] After gaining access to cached data, an adversary looks for potentially sensitive information and stores it for malicious use. This sensitive data could possibly be used in follow-up attacks related to authentication or authorization. | techniques: Using a public computer, or gaining access to a victim's computer, examine browser cache to look fo…

## Prerequisites

- The target application must store sensitive information in a cache.
- The cache must be inadequately protected against attacker access.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- The attacker must be able to reach the target application's cache. This may require prior access to the machine on which the target application runs. If the cache is encrypted, the attacker would need sufficient computational resources to crack the encryption. With strong encryption schemes, doing this could be intractable, but weaker encryption schemes could allow an attacker with sufficient res…

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-167](CAPEC-167.md)
- CanPrecede → [CAPEC-560](CAPEC-560.md)

## Related CWEs (run the cwe skill)

- [CWE-524](../cwe/references/CWE-524.md) — run that CWE procedure after this CAPEC flow
- [CWE-311](../cwe/references/CWE-311.md) — run that CWE procedure after this CAPEC flow
- [CWE-1239](../cwe/references/CWE-1239.md) — run that CWE procedure after this CAPEC flow
- [CWE-1258](../cwe/references/CWE-1258.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-204 and CWE IDs
