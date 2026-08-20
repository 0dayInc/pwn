# CAPEC-654: Credential Prompt Impersonation

- Catalog: [CAPEC-654](https://capec.mitre.org/data/definitions/654.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary, through a previously installed malicious application, impersonates a credential prompt in an attempt to steal a user's credentials.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-654 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-654 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-654`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine suitable tasks to exploit] Determine what tasks exist on the target system that may result in a user providing their credentials. | techniques: Determine what tasks prompt a user for their credentials.
- Step 2 (Exploit): [Impersonate Task] Impersonate a legitimate task, either expected or unexpected, in an attempt to gain user credentials. | techniques: Prompt a user for their credentials, while making the user believe the credential request is legitimate.

## Prerequisites

- The adversary must already have access to the target system via some means.
- A legitimate task must exist that an adversary can impersonate to glean credentials.

## Skills required

- Low: Once an adversary has gained access to the target system, impersonating a credential prompt is not difficult.

## Resources required

- Malware or some other means to initially comprise the target system.
- Additional malware to impersonate a legitimate credential prompt.

## Oracles (consequences)

- Access Control, Authentication: Gain Privileges

## Mitigations to bypass

- The only known mitigation to this attack is to avoid installing the malicious application on the device. However, to impersonate a running task the malicious application does need the GET_TASKS permission to be able to query the task list, and being suspicious of applications with that permission can help.

## Example instances (payload / topology hints)

- An adversary monitors the system task list for Microsoft Outlook in an attempt to determine when the application may prompt the user to enter their credentials to view encrypted email. Once the task is executed, the adversary impersonates the credential prompt to obtain the user's Microsoft Outlook encryption credentials. These credentials can then be leveraged by the adversary to read a user's e…
- An adversary randomly prompts a user to enter their system credentials, tricking the user into believing that a background process requires the credentials to function. The adversary can then use these gleaned credentials to execute additional attacks or obtain data.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-504](CAPEC-504.md)

## Related CWEs (run the cwe skill)

- [CWE-1021](../cwe/references/CWE-1021.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-654 and CWE IDs
