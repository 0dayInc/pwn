# CAPEC-652: Use of Known Kerberos Credentials

- Catalog: [CAPEC-652](https://capec.mitre.org/data/definitions/652.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary obtains (i.e. steals or purchases) legitimate Kerberos credentials (e.g. Kerberos service account userID/password or Kerberos Tickets) with the goal of achieving authenticated access to additional systems, applications, or services within the domain.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-652 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-652 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-652`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Acquire known Kerberos credentials] The adversary must obtain known Kerberos credentials in order to access the target system, application, or service within the domain. | techniques: An adversary purchases breached Kerberos service account username/password combinations or leaked hashed passwords from the dark web.; An adversary guesses the credentials to a weak Kerberos servi…
- Step 2 (Experiment): [Attempt Kerberos authentication] Try each Kerberos credential against various resources within the domain until the target grants access. | techniques: Manually or automatically enter each Kerberos service account credential through the target's interface.; Attempt a Pass the Ticket attack.
- Step 3 (Exploit): [Impersonate] An adversary can use successful experiments or authentications to impersonate an authorized user or system, or to laterally move within the domain
- Step 4 (Exploit): [Spoofing] Malicious data can be injected into the target system or into other systems on the domain. The adversary can also pose as a legitimate domain user to perform social engineering attacks.
- Step 5 (Exploit): [Data Exfiltration] The adversary can obtain sensitive data contained within domain systems or applications.

## Prerequisites

- The system/application leverages Kerberos authentication.
- The system/application uses one factor password-based authentication, SSO, and/or cloud-based authentication for Kerberos service accounts.
- The system/application does not have a sound password policy that is being enforced for Kerberos service accounts.
- The system/application does not implement an effective password throttling mechanism for authenticating to Kerberos service accounts.
- The targeted network allows for network sniffing attacks to succeed.

## Skills required

- Low: Once an adversary obtains a known Kerberos credential, leveraging it is trivial.

## Resources required

- A valid Kerberos ticket or a known Kerberos service account credential.

## Oracles (consequences)

- Confidentiality, Access Control, Authentication: Gain Privileges
- Confidentiality, Authorization: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Create a strong password policy and ensure that your system enforces this policy for Kerberos service accounts.
- Ensure Kerberos service accounts are not reusing username/password combinations for multiple systems, applications, or services.
- Do not reuse Kerberos service account credentials across systems.
- Deny remote use of Kerberos service account credentials to log into domain systems.
- Do not allow Kerberos service accounts to be a local administrator on more than one system.
- Enable at least AES Kerberos encryption for tickets.
- Monitor system and domain logs for abnormal credential access.

## Example instances (payload / topology hints)

- Bronze Butler (also known as Tick), has been shown to leverage forged Kerberos Ticket Granting Tickets (TGTs) and Ticket Granting Service (TGS) tickets to maintain administrative access on a number of systems. [REF-584]
- PowerSploit's Invoke-Kerberoast module can be leveraged to request Ticket Granting Service (TGS) tickets and return crackable ticket hashes. [REF-585] [REF-586]

## Related CAPECs (test these too)

- ChildOf → [CAPEC-560](CAPEC-560.md)
- CanPrecede → [CAPEC-151](CAPEC-151.md)

## Related CWEs (run the cwe skill)

- [CWE-522](../cwe/references/CWE-522.md) — run that CWE procedure after this CAPEC flow
- [CWE-307](../cwe/references/CWE-307.md) — run that CWE procedure after this CAPEC flow
- [CWE-308](../cwe/references/CWE-308.md) — run that CWE procedure after this CAPEC flow
- [CWE-309](../cwe/references/CWE-309.md) — run that CWE procedure after this CAPEC flow
- [CWE-262](../cwe/references/CWE-262.md) — run that CWE procedure after this CAPEC flow
- [CWE-263](../cwe/references/CWE-263.md) — run that CWE procedure after this CAPEC flow
- [CWE-654](../cwe/references/CWE-654.md) — run that CWE procedure after this CAPEC flow
- [CWE-294](../cwe/references/CWE-294.md) — run that CWE procedure after this CAPEC flow
- [CWE-836](../cwe/references/CWE-836.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-652 and CWE IDs
