# CAPEC-144: Detect Unpublicized Web Services

- Catalog: [CAPEC-144](https://capec.mitre.org/data/definitions/144.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

An adversary searches a targeted web site for web services that have not been publicized. This attack can be especially dangerous since unpublished but available services may not have adequate security controls placed upon them given that an administrator may believe they are unreachable.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-144 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-144 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-144`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find target web site] An adversary finds a target web site that they think may have unpublicized web services
- Step 2 (Explore): [Map the published web site] The adversary will map the published web site either by using an automated tool or by manually accessing well-known debugging or logging pages, or otherwise predictable pages within the site tree | techniques: Use Dirbuster to brute force directories and file names to find unpublicized web services; Find a pattern in the naming of documents and extra…
- Step 3 (Experiment): [Try to find weaknesses or information] The adversary will try to find weaknesses in the unpublicized services that the targeted site did not intend to be public | techniques: Use Nikto to look for web service vulnerabilities
- Step 4 (Exploit): [Follow-up attack] Use any information or weaknesses found to carry out a follow-up attack

## Prerequisites

- The targeted web site must include unpublished services within its web tree. The nature of these services determines the severity of this attack.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- Spidering tools to explore the target web site are extremely useful in this attack especially when attacking large sites. Some tools might also be able to automatically construct common service queries from known paths.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-150](CAPEC-150.md)

## Related CWEs (run the cwe skill)

- [CWE-425](../cwe/references/CWE-425.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-144 and CWE IDs
