# CAPEC-459: Creating a Rogue Certification Authority Certificate

- Catalog: [CAPEC-459](https://capec.mitre.org/data/definitions/459.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits a weakness resulting from using a hashing algorithm with weak collision resistance to generate certificate signing requests (CSR) that contain collision blocks in their "to be signed" parts. The adversary submits one CSR to be signed by a trusted certificate authority then uses the signed blob to make a second certificate appear signed by said certificate authority. Due to the hash collision, both certificates, though different, hash to the same value and so the signed blob works just as well in the second certificate. The net effect is that the adversary's second X.509 certificate, which the Certification Authority has never seen, is now signed and validated by that Certification Authority.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-459 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-459 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-459`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Experiment): [Craft Certificates] The adversary crafts two different, but valid X.509 certificates that when hashed with an insufficiently collision resistant hashing algorithm would yield the same value.
- Step 2 (Experiment): [Send CSR to Certificate Authority] The adversary sends the CSR for one of the certificates to the Certification Authority which uses the targeted hashing algorithm. That request is completely valid and the Certificate Authority issues an X.509 certificate to the adversary which is signed with its private key.
- Step 3 (Exploit): [Insert Signed Blob into Unsigned Certificate] The adversary takes the signed blob and inserts it into the second X.509 certificate that the attacker generated. Due to the hash collision, both certificates, though different, hash to the same value and so the signed blob is valid in the second certificate. The result is two certificates that appear to be signed by a valid certifi…

## Prerequisites

- Certification Authority is using a hash function with insufficient collision resistance to generate the certificate hash to be signed

## Skills required

- High: Understanding of how to force a hash collision in X.509 certificates
- High: An attacker must be able to craft two X.509 certificates that produce the same hash value
- Medium: Knowledge needed to set up a certification authority

## Resources required

- Knowledge of a certificate authority that uses hashing algorithms with poor collision resistance
- A valid certificate request and a malicious certificate request with identical hash values

## Oracles (consequences)

- Access Control, Authentication: Gain Privileges

## Mitigations to bypass

- Certification Authorities need to stop using deprecated or cryptographically insecure hashing algorithms to hash the certificates that they are about to sign. Instead they should be using stronger hashing functions such as SHA-256 or SHA-512.

## Example instances (payload / topology hints)

- MD5 Collisions The MD5 algorithm is not collision resistant, allowing attackers to use spoofing attacks to create rogue certificate Authorities. See also: CVE-2004-2761
- SHA1 Collisions The SHA1 algorithm is not collision resistant, allowing attackers to use spoofing attacks to create rogue certificate Authorities. See also: CVE-2005-4900
- PKI Infrastructure vulnerabilities Research has show significant vulnerabilities in PKI infrastructure. Trusted certificate authorities have been shown to use weak hashing algorithms after attacks have been demonstrated against those algorithms. Additionally, reliable methods have been demonstrated for generated MD5 collisions that could be used to generate malicious CSRs.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-473](CAPEC-473.md)

## Related CWEs (run the cwe skill)

- [CWE-327](../cwe/references/CWE-327.md) — run that CWE procedure after this CAPEC flow
- [CWE-295](../cwe/references/CWE-295.md) — run that CWE procedure after this CAPEC flow
- [CWE-290](../cwe/references/CWE-290.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-459 and CWE IDs
