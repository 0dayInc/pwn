# CAPEC-70: Try Common or Default Usernames and Passwords

- Catalog: [CAPEC-70](https://capec.mitre.org/data/definitions/70.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary may try certain common or default usernames and passwords to gain access into the system and perform unauthorized actions. An adversary may try an intelligent brute force using empty passwords, known vendor default credentials, as well as a dictionary of common usernames and passwords. Many vendor products come preconfigured with default (and thus well-known) usernames and passwords that should be deleted prior to usage in a production environment. It is a common mistake to forget to remove these default login credentials. Another problem is that users would pick very simple (common) passwords (e.g. "secret" or "password") that make it easier for the attacker to gain access to the system compared to using a brute force attack or even a dictionary attack using a full dictionary.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-70 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-70 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-70`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The system uses one factor password based authentication.The adversary has the means to interact with the system.

## Skills required

- Low: An adversary just needs to gain access to common default usernames/passwords specific to the technologies used by the system. Additionally, a brute force attack leveraging common passwords can be easily realized if the user name is known.

## Resources required

- Technology or vendor specific list of default usernames and passwords.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Delete all default account credentials that may be put in by the product vendor.
- Implement a password throttling mechanism. This mechanism should take into account both the IP address and the log in name of the user.
- Put together a strong password policy and make sure that all user created passwords comply with it. Alternatively automatically generate strong passwords for users.
- Passwords need to be recycled to prevent aging, that is every once in a while a new password must be chosen.

## Example instances (payload / topology hints)

- A user sets their password to "123" or intentionally leaves their password blank. If the system does not have password strength enforcement against a sound password policy, this password may be admitted. Passwords like these two examples are two simple and common passwords that are easily able to be guessed by the adversary.
- Cisco 2700 Series Wireless Location Appliances (version 2.1.34.0 and earlier) have a default administrator username "root" with a password "password". This allows remote attackers to easily obtain administrative privileges. See also: CVE-2006-5288
- In April 2019, adversaries attacked several popular IoT devices (a VOIP phone, an office printer, and a video decoder) across multiple customer locations. An investigation conducted by the Microsoft Security Resposne Center (MSRC) discovered that these devices were used to gain initial access to corporate networks. In two of the cases, the passwords for the devices were deployed without changing…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-49](CAPEC-49.md)
- CanPrecede → [CAPEC-600](CAPEC-600.md)
- CanPrecede → [CAPEC-151](CAPEC-151.md)
- CanPrecede → [CAPEC-560](CAPEC-560.md)
- CanPrecede → [CAPEC-561](CAPEC-561.md)
- CanPrecede → [CAPEC-653](CAPEC-653.md)

## Related CWEs (run the cwe skill)

- [CWE-521](../cwe/references/CWE-521.md) — run that CWE procedure after this CAPEC flow
- [CWE-262](../cwe/references/CWE-262.md) — run that CWE procedure after this CAPEC flow
- [CWE-263](../cwe/references/CWE-263.md) — run that CWE procedure after this CAPEC flow
- [CWE-798](../cwe/references/CWE-798.md) — run that CWE procedure after this CAPEC flow
- [CWE-654](../cwe/references/CWE-654.md) — run that CWE procedure after this CAPEC flow
- [CWE-308](../cwe/references/CWE-308.md) — run that CWE procedure after this CAPEC flow
- [CWE-309](../cwe/references/CWE-309.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-70 and CWE IDs
