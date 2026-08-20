# CAPEC-600: Credential Stuffing

- Catalog: [CAPEC-600](https://capec.mitre.org/data/definitions/600.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary tries known username/password combinations against different systems, applications, or services to gain additional authenticated access. Credential Stuffing attacks rely upon the fact that many users leverage the same username/password combination for multiple systems, applications, and services.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-600 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-600 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-600`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Acquire known credentials] The adversary must obtain known credentials in order to access the target system, application, or service. | techniques: An adversary purchases breached username/password combinations or leaked hashed passwords from the dark web.; An adversary leverages a key logger or phishing attack to steal user credentials as they are provided.; An adversary condu…
- Step 2 (Explore): [Determine target's password policy] Determine the password policies of the target system/application to determine if the known credentials fit within the specified criteria. | techniques: Determine minimum and maximum allowed password lengths.; Determine format of allowed passwords (whether they are required or allowed to contain numbers, special characters, etc., or whether th…
- Step 3 (Experiment): [Attempt authentication] Try each username/password combination until the target grants access. | techniques: Manually or automatically enter each username/password combination through the target's interface.
- Step 3 (Exploit): [Impersonate] An adversary can use successful experiments or authentications to impersonate an authorized user or system or to laterally move within a system or application
- Step 4 (Exploit): [Spoofing] Malicious data can be injected into the target system or into a victim user's system by an adversary. The adversary can also pose as a legitimate user to perform social engineering attacks.
- Step 5 (Exploit): [Data Exfiltration] The adversary can obtain sensitive data contained within the system or application.

## Prerequisites

- The system/application uses one factor password based authentication, SSO, and/or cloud-based authentication.
- The system/application does not have a sound password policy that is being enforced.
- The system/application does not implement an effective password throttling mechanism.
- The adversary possesses a list of known user accounts and corresponding passwords that may exist on the target.

## Skills required

- Low: A Credential Stuffing attack is very straightforward.

## Resources required

- A machine with sufficient resources for the job (e.g. CPU, RAM, HD).
- A known list of username/password combinations.
- A custom script that leverages the credential list to launch the attack.

## Oracles (consequences)

- Confidentiality, Access Control, Authentication: Gain Privileges
- Confidentiality, Authorization: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain network.
- Create a strong password policy and ensure that your system enforces this policy.
- Ensure users are not reusing username/password combinations for multiple systems, applications, or services.
- Do not reuse local administrator account credentials across systems.
- Deny remote use of local admin credentials to log into domain systems.
- Do not allow accounts to be a local administrator on more than one system.
- Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-2.
- Monitor system and domain logs for abnormal credential access.

## Example instances (payload / topology hints)

- A user leverages the password "Password123" for a handful of application logins. An adversary obtains a victim's username/password combination from a breach of a social media application and executes a Credential Stuffing attack against multiple banking and credit card applications. Since the user leverages the same credentials for their bank account login, the adversary successfully authenticate…
- In October 2014 J.P. Morgan's Corporate Challenge website was breached, resulting in adversaries obtaining multiple username/password pairs. A Credential Stuffing attack was then executed against J.P. Morgan Chase, which resulted in over 76 million households having their accounts compromised.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-560](CAPEC-560.md)
- CanPrecede → [CAPEC-151](CAPEC-151.md)
- CanPrecede → [CAPEC-653](CAPEC-653.md)

## Related CWEs (run the cwe skill)

- [CWE-522](../cwe/references/CWE-522.md) — run that CWE procedure after this CAPEC flow
- [CWE-307](../cwe/references/CWE-307.md) — run that CWE procedure after this CAPEC flow
- [CWE-308](../cwe/references/CWE-308.md) — run that CWE procedure after this CAPEC flow
- [CWE-309](../cwe/references/CWE-309.md) — run that CWE procedure after this CAPEC flow
- [CWE-262](../cwe/references/CWE-262.md) — run that CWE procedure after this CAPEC flow
- [CWE-263](../cwe/references/CWE-263.md) — run that CWE procedure after this CAPEC flow
- [CWE-654](../cwe/references/CWE-654.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-600 and CWE IDs
