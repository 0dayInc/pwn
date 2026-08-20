# CAPEC-565: Password Spraying

- Catalog: [CAPEC-565](https://capec.mitre.org/data/definitions/565.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

In a Password Spraying attack, an adversary tries a small list (e.g. 3-5) of common or expected passwords, often matching the target's complexity policy, against a known list of user accounts to gain valid credentials. The adversary tries a particular password for each user account, before moving onto the next password in the list. This approach assists the adversary in remaining undetected by avoiding rapid or frequent account lockouts. The adversary may then reattempt the process with additional passwords, once enough time has passed to prevent inducing a lockout.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-565 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-565 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-565`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine target's password policy] Determine the password policies of the target system/application. | techniques: Determine minimum and maximum allowed password lengths.; Determine format of allowed passwords (whether they are required or allowed to contain numbers, special characters, etc., or whether they are allowed to contain words from the dictionary).; Determine account…
- Step 2 (Explore): [Select passwords] Pick the passwords to be used in the attack (e.g. commonly used passwords, passwords tailored to individual users, etc.) | techniques: Select passwords based on common use or a particular user's additional details.; Select passwords based on the target's password complexity policies.
- Step 3 (Exploit): [Brute force password] Given the finite space of possible passwords dictated by information determined in the previous steps, try each password for all known user accounts until the target grants access. | techniques: Manually or automatically enter the first password for each known user account through the target's interface. In most systems, start with the shortest and simples…

## Prerequisites

- The system/application uses one factor password based authentication.
- The system/application does not have a sound password policy that is being enforced.
- The system/application does not implement an effective password throttling mechanism.
- The adversary possesses a list of known user accounts on the target system/application.

## Skills required

- Low: A Password Spraying attack is very straightforward. A variety of password cracking tools are widely available.

## Resources required

- A machine with sufficient resources for the job (e.g. CPU, RAM, HD).
- Applicable password lists.
- A password cracking tool or a custom script that leverages the password list to launch the attack.

## Oracles (consequences)

- Confidentiality, Access Control, Authentication: Gain Privileges
- Confidentiality, Authorization: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Create a strong password policy and ensure that your system enforces this policy.
- Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-2.
- Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain network.

## Example instances (payload / topology hints)

- A user selects the phrase "Password123" as their password, believing that it would be very difficult to guess. Password Spraying, leveraging a list of commonly used passwords, is used to crack this password and gain access to the account.
- The Iranian hacker group APT33 (AKA Holmium, Refined Kitten, or Elfin) carried out numerous Password Spraying attacks in 2019. On average, APT33 targeted 2,000 organizations per month, with upwards of 10 million authentication attempts each day. The majority of these attacks targeted manufacturers, suppliers, or maintainers of industrial control system equipment.

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
- [CWE-654](../cwe/references/CWE-654.md) — run that CWE procedure after this CAPEC flow
- [CWE-307](../cwe/references/CWE-307.md) — run that CWE procedure after this CAPEC flow
- [CWE-308](../cwe/references/CWE-308.md) — run that CWE procedure after this CAPEC flow
- [CWE-309](../cwe/references/CWE-309.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-565 and CWE IDs
