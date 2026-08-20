# CAPEC-609: Cellular Traffic Intercept

- Catalog: [CAPEC-609](https://capec.mitre.org/data/definitions/609.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

Cellular traffic for voice and data from mobile devices and retransmission devices can be intercepted via numerous methods. Malicious actors can deploy their own cellular tower equipment and intercept cellular traffic surreptitiously. Additionally, government agencies of adversaries and malicious actors can intercept cellular traffic via the telecommunications backbone over which mobile traffic is transmitted.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-609 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-609 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-609`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- None

## Skills required

- Medium: Adversaries can purchase hardware and software solutions, or create their own solutions, to capture/intercept cellular radio traffic. The cost of a basic Base Transceiver Station (BTS) to broadcast to local mobile cellular radios in mobile devices has dropped to very affordable costs. The ability o…

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality: Read Data — Capture all cellular and RF traffic from mobile and retransmission devices. Move bulk traffic capture to storage area for cryptanalysis of encrypted traffic, and telemetry analysis of non-encrypted data. (packet headers, cellular power data, signal strength, etc.)

## Mitigations to bypass

- Encryption of all data packets emanating from the smartphone to a retransmission device via two encrypted tunnels with Suite B cryptography, all the way to the VPN gateway at the datacenter.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-157](CAPEC-157.md)

## Related CWEs (run the cwe skill)

- [CWE-311](../cwe/references/CWE-311.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-609 and CWE IDs
