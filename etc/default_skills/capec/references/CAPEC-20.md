# CAPEC-20: Encryption Brute Forcing

- Catalog: [CAPEC-20](https://capec.mitre.org/data/definitions/20.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Low · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

An attacker, armed with the cipher text and the encryption algorithm used, performs an exhaustive (brute force) search on the key space to determine the key that decrypts the cipher text to obtain the plaintext.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-20 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-20 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-20`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): Determine the ciphertext and the encryption algorithm.
- Step 2 (Experiment): Perform an exhaustive brute force search of the key space, producing candidate plaintexts and observing if they make sense.

## Prerequisites

- Ciphertext is known.
- Encryption algorithm and key size are known.

## Skills required

- Low: Brute forcing encryption does not require much skill.

## Resources required

- A powerful enough computer for the job with sufficient CPU, RAM and HD. Exact requirements will depend on the size of the brute force job and the time requirement for completion. Some brute forcing jobs may require grid or distributed computing (e.g. DES Challenge). On average, for a binary key of size N, 2^(N/2) trials will be needed to find the key that would decrypt the ciphertext to obtain th…

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.
- In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

## Example instances (payload / topology hints)

- In 1997 the original DES challenge used distributed net computing to brute force the encryption key and decrypt the ciphertext to obtain the original plaintext. Each machine was given its own section of the key space to cover. The ciphertext was decrypted in 96 days.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-112](CAPEC-112.md)
- CanPrecede → [CAPEC-668](CAPEC-668.md)

## Related CWEs (run the cwe skill)

- [CWE-326](../cwe/references/CWE-326.md) — run that CWE procedure after this CAPEC flow
- [CWE-327](../cwe/references/CWE-327.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow
- [CWE-1204](../cwe/references/CWE-1204.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-20 and CWE IDs
