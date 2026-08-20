# CAPEC-561: Windows Admin Shares with Stolen Credentials

- Catalog: [CAPEC-561](https://capec.mitre.org/data/definitions/561.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: not stated
- CAPEC list: 3.9

## Attack pattern

An adversary guesses or obtains (i.e. steals or purchases) legitimate Windows administrator credentials (e.g. userID/password) to access Windows Admin Shares on a local machine or within a Windows domain.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-561 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-561 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-561`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Acquire known Windows administrator credentials] The adversary must obtain known Windows administrator credentials in order to access the administrative network shares. | techniques: An adversary purchases breached Windows administrator credentials from the dark web.; An adversary leverages a key logger or phishing attack to steal administrator credentials as they are provided.…
- Step 2 (Experiment): [Attempt domain authentication] Try each Windows administrator credential against the hidden network shares until the target grants access. | techniques: Manually or automatically enter each administrator credential through the target's interface.
- Step 3 (Exploit): [Malware Execution] An adversary can remotely execute malware within the administrative network shares to infect other systems within the domain.
- Step 4 (Exploit): [Data Exfiltration] The adversary can remotely obtain sensitive data contained within the administrative network shares.

## Prerequisites

- The system/application is connected to the Windows domain.
- The target administrative share allows remote use of local admin credentials to log into domain systems.
- The adversary possesses a list of known Windows administrator credentials that exist on the target domain.

## Skills required

- Low: Once an adversary obtains a known Windows credential, leveraging it is trivial.

## Resources required

- A list of known Windows administrator credentials for the targeted domain.

## Oracles (consequences)

- Confidentiality, Access Control, Authentication: Gain Privileges
- Confidentiality, Authorization: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Do not reuse local administrator account credentials across systems.
- Deny remote use of local admin credentials to log into domain systems.
- Do not allow accounts to be a local administrator on more than one system.

## Example instances (payload / topology hints)

- APT32 has leveraged Windows' built-in Net utility to use Windows Administrative Shares to copy and execute remote malware. [REF-579]
- In May 2017, APT15 laterally moved within a Windows domain via Windows Administrative Shares to copy files to and from compromised host systems. This further allowed for the remote execution of malware. [REF-578]

## Related CAPECs (test these too)

- ChildOf → [CAPEC-653](CAPEC-653.md)
- CanPrecede → [CAPEC-151](CAPEC-151.md)
- CanPrecede → [CAPEC-165](CAPEC-165.md)
- CanPrecede → [CAPEC-549](CAPEC-549.md)
- CanPrecede → [CAPEC-545](CAPEC-545.md)

## Related CWEs (run the cwe skill)

- [CWE-522](../cwe/references/CWE-522.md) — run that CWE procedure after this CAPEC flow
- [CWE-308](../cwe/references/CWE-308.md) — run that CWE procedure after this CAPEC flow
- [CWE-309](../cwe/references/CWE-309.md) — run that CWE procedure after this CAPEC flow
- [CWE-294](../cwe/references/CWE-294.md) — run that CWE procedure after this CAPEC flow
- [CWE-263](../cwe/references/CWE-263.md) — run that CWE procedure after this CAPEC flow
- [CWE-262](../cwe/references/CWE-262.md) — run that CWE procedure after this CAPEC flow
- [CWE-521](../cwe/references/CWE-521.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-561 and CWE IDs
