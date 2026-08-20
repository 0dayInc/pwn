# CAPEC-625: Mobile Device Fault Injection

- Catalog: [CAPEC-625](https://capec.mitre.org/data/definitions/625.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: not stated · Typical severity: not stated
- CAPEC list: 3.9

## Attack pattern

Fault injection attacks against mobile devices use disruptive signals or events (e.g. electromagnetic pulses, laser pulses, clock glitches, etc.) to cause faulty behavior. When performed in a controlled manner on devices performing cryptographic operations, this faulty behavior can be exploited to derive secret key information. Although this attack usually requires physical control of the mobile device, it is non-destructive, and the device can be used after the attack without any indication that secret keys were compromised.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-625 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-625 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-625`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- (none listed in CAPEC catalog)

## Skills required

- High: Adversaries require non-trivial technical skills to create and implement fault injection attacks on mobile devices. Although this style of attack has become easier (commercial equipment and training classes are available to perform these attacks), they usual require significant setup and experiment…

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Access Control: Read Data — Extract long-term secret keys (e.g. keys used for VPN or WiFi authentication and encryption) to enable decryption of intercepted VOIP traffic.

## Mitigations to bypass

- Strong physical security of all devices that contain secret key information. (even when devices are not in use)
- Frequent changes to secret keys and certificates.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-624](CAPEC-624.md)

## Related CWEs (run the cwe skill)

- [CWE-1247](../cwe/references/CWE-1247.md) — run that CWE procedure after this CAPEC flow
- [CWE-1248](../cwe/references/CWE-1248.md) — run that CWE procedure after this CAPEC flow
- [CWE-1256](../cwe/references/CWE-1256.md) — run that CWE procedure after this CAPEC flow
- [CWE-1319](../cwe/references/CWE-1319.md) — run that CWE procedure after this CAPEC flow
- [CWE-1332](../cwe/references/CWE-1332.md) — run that CWE procedure after this CAPEC flow
- [CWE-1334](../cwe/references/CWE-1334.md) — run that CWE procedure after this CAPEC flow
- [CWE-1338](../cwe/references/CWE-1338.md) — run that CWE procedure after this CAPEC flow
- [CWE-1351](../cwe/references/CWE-1351.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-625 and CWE IDs
