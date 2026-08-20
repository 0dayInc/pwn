# CAPEC-206: Signing Malicious Code

- Catalog: [CAPEC-206](https://capec.mitre.org/data/definitions/206.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

The adversary extracts credentials used for code signing from a production environment and then uses these credentials to sign malicious content with the developer's key. Many developers use signing keys to sign code or hashes of code. When users or applications verify the signatures are accurate they are led to believe that the code came from the owner of the signing key and that the code has not been modified since the signature was applied. If the adversary has extracted the signing credentials then they can use those credentials to sign their own code bundles. Users or tools that verify the signatures attached to the code will likely assume the code came from the legitimate developer and install or run the code, effectively allowing the adversary to execute arbitrary code on the victim's computer. This differs from CAPEC-673, because the adversary is performing the code signing.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-206 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-206 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-206`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): The adversary first attempts to obtain a digital certificate in order to sign their malware or tools. This certificate could be stolen, created by the adversary, or acquired normally through a certificate authority.
- Step 2 (Explore): Based on the type of certificate obtained, the adversary will create a goal for their attack. This is either a broad or targeted attack. If an adversary was able to steal a certificate from a targeted organization, they could target this organization by pretending to have legitimate code signed by them. In other cases, the adversary would simply sign their malware and pose as le…
- Step 3 (Experiment): The adversary creates their malware and signs it with the obtained digital certificate. The adversary then checks if the code that they signed is valid either through downloading from the targeted source or testing locally.
- Step 4 (Exploit): Once the malware has been signed, it is then deployed to the desired location. They wait for a trusting user to run their malware, thinking that it is legitimate software. This malware could do a variety of things based on the motivation of the adversary.

## Prerequisites

- The targeted developer must use a signing key to sign code bundles. (Note that not doing this is not a defense - it only means that the adversary does not need to steal the signing key before forging code bundles in the developer's name.)

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Ensure digital certificates are protected and inaccessible by unauthorized uses.
- If a digital certificate has been compromised it should be revoked and regenerated.
- Even if a piece of software has a valid and trusted digital signature, it should be assessed for any weaknesses and vulnerabilities.

## Example instances (payload / topology hints)

- In the famous Stuxnet malware incident, two digital certificates were compromised in order to sign malicious device drivers with legitimate credentials. The signing resulted in the malware appearing as trusted by the system it was running on, which facilitated the installation of the malware in kernel mode. This further resulted in Stuxnet remaining undetected for a significant amount of time. [R…
- The cyber espionage group CyberKittens leveraged a stolen certificate from AI Squared that allowed them to leverage a signed executable within Operation Wilted Tulip. This ultimately allowed the executable to run as trusted on the system, allowing a Crowd Strike stager to be loaded within the system's memory. [REF-714]

## Related CAPECs (test these too)

- ChildOf → [CAPEC-444](CAPEC-444.md)

## Related CWEs (run the cwe skill)

- [CWE-732](../cwe/references/CWE-732.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-206 and CWE IDs
