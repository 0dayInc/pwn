# CAPEC-97: Cryptanalysis

- Catalog: [CAPEC-97](https://capec.mitre.org/data/definitions/97.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Low · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

Cryptanalysis is a process of finding weaknesses in cryptographic algorithms and using these weaknesses to decipher the ciphertext without knowing the secret key (instance deduction). Sometimes the weakness is not in the cryptographic algorithm itself, but rather in how it is applied that makes cryptanalysis successful. An attacker may have other goals as well, such as: Total Break (finding the secret key), Global Deduction (finding a functionally equivalent algorithm for encryption and decryption that does not require knowledge of the secret key), Information Deduction (gaining some information about plaintexts or ciphertexts that was not previously known) and Distinguishing Algorithm (the attacker has the ability to distinguish the output of the encryption (ciphertext) from a random permutation of bits).

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-97 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-97 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-97`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): An attacker discovers a weakness in the cryptographic algorithm or a weakness in how it was applied to a particular chunk of plaintext.
- Step 2 (Exploit): An attacker leverages the discovered weakness to decrypt, partially decrypt or infer some information about the contents of the encrypted message. All of that is done without knowing the secret key.

## Prerequisites

- The target software utilizes some sort of cryptographic algorithm.
- An underlying weaknesses exists either in the cryptographic algorithm used or in the way that it was applied to a particular chunk of plaintext.
- The encryption algorithm is known to the attacker.
- An attacker has access to the ciphertext.

## Skills required

- High: Cryptanalysis generally requires a very significant level of understanding of mathematics and computation.

## Resources required

- Computing resource requirements will vary based on the complexity of a given cryptanalysis technique. Access to the encryption/decryption routines of the algorithm is also required.

## Oracles (consequences)

- Confidentiality: Read Data — In most cases, if cryptanalysis is successful at all, an adversary will not be able to decrypt the entire message, but instead will only be able to deduce some information about the plaintext. However, that may be sufficient for an adversary, depending on the context of the attack.

## Mitigations to bypass

- Use proven cryptographic algorithms with recommended key sizes.
- Ensure that the algorithms are used properly. That means: 1. Not rolling out your own crypto; Use proven algorithms and implementations. 2. Choosing initialization vectors with sufficiently random numbers 3. Generating key material using good sources of randomness and avoiding known weak keys 4. Using proven protocols and their implementations. 5. Picking the most appropriate cryptographic algori…

## Example instances (payload / topology hints)

- A very easy to understand example is a cryptanalysis technique called frequency analysis that can be successfully applied to the very basic classic encryption algorithms that performed mono-alphabetic substitution replacing each letter in the plaintext with its predetermined mapping letter from the same alphabet. This was considered an improvement over a more basic technique that would simply shi…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-192](CAPEC-192.md)
- CanPrecede → [CAPEC-20](CAPEC-20.md)

## Related CWEs (run the cwe skill)

- [CWE-327](../cwe/references/CWE-327.md) — run that CWE procedure after this CAPEC flow
- [CWE-1204](../cwe/references/CWE-1204.md) — run that CWE procedure after this CAPEC flow
- [CWE-1240](../cwe/references/CWE-1240.md) — run that CWE procedure after this CAPEC flow
- [CWE-1241](../cwe/references/CWE-1241.md) — run that CWE procedure after this CAPEC flow
- [CWE-1279](../cwe/references/CWE-1279.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-97 and CWE IDs
