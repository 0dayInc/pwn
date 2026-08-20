# CAPEC-644: Use of Captured Hashes (Pass The Hash)

- Catalog: [CAPEC-644](https://capec.mitre.org/data/definitions/644.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary obtains (i.e. steals or purchases) legitimate Windows domain credential hash values to access systems within the domain that leverage the Lan Man (LM) and/or NT Lan Man (NTLM) authentication protocols.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-644 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-644 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-644`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Acquire known Windows credential hash value pairs] The adversary must obtain known Windows credential hash value pairs of accounts that exist on the domain. | techniques: An adversary purchases breached Windows credential hash value pairs from the dark web.; An adversary conducts a sniffing attack to steal Windows credential hash value pairs as they are transmitted.; An adversa…
- Step 2 (Experiment): [Attempt domain authentication] Try each Windows credential hash value pair until the target grants access. | techniques: Manually or automatically enter each Windows credential hash value pair through the target's interface.
- Step 3 (Exploit): [Impersonate] An adversary can use successful experiments or authentications to impersonate an authorized user or system, or to laterally move within the domain
- Step 4 (Exploit): [Spoofing] Malicious data can be injected into the target system or into other systems on the domain. The adversary can also pose as a legitimate domain user to perform social engineering attacks.
- Step 5 (Exploit): [Data Exfiltration] The adversary can obtain sensitive data contained within domain systems or applications.

## Prerequisites

- The system/application is connected to the Windows domain.
- The system/application leverages the Lan Man (LM) and/or NT Lan Man (NTLM) authentication protocols.
- The adversary possesses known Windows credential hash value pairs that exist on the target domain.

## Skills required

- Low: Once an adversary obtains a known Windows credential hash value pair, leveraging it is trivial.

## Resources required

- A list of known Window credential hash value pairs for the targeted domain.

## Oracles (consequences)

- Confidentiality, Access Control, Authentication: Gain Privileges
- Confidentiality, Authorization: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Prevent the use of Lan Man and NT Lan Man authentication on severs and apply patch KB2871997 to Windows 7 and higher systems.
- Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain network.
- Monitor system and domain logs for abnormal credential access.
- Create a strong password policy and ensure that your system enforces this policy.
- Leverage system penetration testing and other defense in depth methods to determine vulnerable systems within a domain.

## Example instances (payload / topology hints)

- Adversaries exploited the Zoom video conferencing application during the 2020 COVID-19 pandemic to exfiltrate Windows domain credential hash value pairs from a target system. The attack entailed sending Universal Naming Convention (UNC) paths within the Zoom chat window of an unprotected Zoom call. If the victim clicked on the link, their Windows usernames and the corresponding Net-NTLM-v2 hashes…
- Operation Soft Cell, which has been underway since at least 2012, leveraged a modified Mimikatz that dumped NTLM hashes. The acquired hashes were then used to authenticate to other systems within the network via Pass The Hash attacks. [REF-580]

## Related CAPECs (test these too)

- ChildOf → [CAPEC-653](CAPEC-653.md)
- CanPrecede → [CAPEC-151](CAPEC-151.md)
- CanPrecede → [CAPEC-165](CAPEC-165.md)
- CanPrecede → [CAPEC-549](CAPEC-549.md)
- CanPrecede → [CAPEC-545](CAPEC-545.md)

## Related CWEs (run the cwe skill)

- [CWE-522](../cwe/references/CWE-522.md) — run that CWE procedure after this CAPEC flow
- [CWE-836](../cwe/references/CWE-836.md) — run that CWE procedure after this CAPEC flow
- [CWE-308](../cwe/references/CWE-308.md) — run that CWE procedure after this CAPEC flow
- [CWE-294](../cwe/references/CWE-294.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-644 and CWE IDs
