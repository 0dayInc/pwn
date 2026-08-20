# CAPEC-16: Dictionary-based Password Attack

- Catalog: [CAPEC-16](https://capec.mitre.org/data/definitions/16.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker tries each of the words in a dictionary as passwords to gain access to the system via some user's account. If the password chosen by the user was a word within the dictionary, this attack will be successful (in the absence of other mitigations). This is a specific instance of the password brute forcing attack pattern. Dictionary Attacks differ from similar attacks such as Password Spraying (CAPEC-565) and Credential Stuffing (CAPEC-600), since they leverage unknown username/password combinations and don't care about inducing account lockouts.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-16 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-16 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-16`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine application's/system's password policy] Determine the password policies of the target application/system. | techniques: Determine minimum and maximum allowed password lengths.; Determine format of allowed passwords (whether they are required or allowed to contain numbers, special characters, etc., or whether they are allowed to contain words from the dictionary).; Det…
- Step 2 (Explore): [Select dictionaries] Pick the dictionaries to be used in the attack (e.g. different languages, specific terminology, etc.) | techniques: Select dictionary based on particular users' preferred languages.; Select dictionary based on the application/system's supported languages.
- Step 3 (Explore): [Determine username(s) to target] Determine username(s) whose passwords to crack. | techniques: Obtain username(s) by sniffing network packets.; Obtain username(s) by querying application/system (e.g. if upon a failed login attempt, the system indicates whether the entered username was valid or not); Obtain usernames from filesystem (e.g. list of directories in C:\Documents and…
- Step 4 (Exploit): [Use dictionary to crack passwords.] Use a password cracking tool that will leverage the dictionary to feed passwords to the system and see if they work. | techniques: Try all words in the dictionary, as well as common misspellings of the words as passwords for the chosen username(s).; Try common combinations of words in the dictionary, as well as common misspellings of the comb…

## Prerequisites

- The system uses one factor password based authentication.
- The system does not have a sound password policy that is being enforced.
- The system does not implement an effective password throttling mechanism.

## Skills required

- Low: A variety of password cracking tools and dictionaries are available to launch this type of an attack.

## Resources required

- A machine with sufficient resources for the job (e.g. CPU, RAM, HD). Applicable dictionaries are required. Also a password cracking tool or a custom script that leverages the dictionary database to launch the attack.

## Oracles (consequences)

- Confidentiality, Access Control, Authentication: Gain Privileges
- Confidentiality: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Create a strong password policy and ensure that your system enforces this policy.
- Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-2.
- Leverage multi-factor authentication for all authentication services.

## Example instances (payload / topology hints)

- A system user selects the word "treacherous" as their passwords believing that it would be very difficult to guess. The password-based dictionary attack is used to crack this password and gain access to the account.
- The Cisco LEAP challenge/response authentication mechanism uses passwords in a way that is susceptible to dictionary attacks, which makes it easier for remote attackers to gain privileges via brute force password guessing attacks. Cisco LEAP is a mutual authentication algorithm that supports dynamic derivation of session keys. With Cisco LEAP, mutual authentication relies on a shared secret, the…

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
- [ ] Finding (if any) cites CAPEC-16 and CWE IDs
