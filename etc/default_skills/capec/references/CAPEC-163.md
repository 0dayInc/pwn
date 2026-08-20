# CAPEC-163: Spear Phishing

- Catalog: [CAPEC-163](https://capec.mitre.org/data/definitions/163.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary targets a specific user or group with a Phishing (CAPEC-98) attack tailored to a category of users in order to have maximum relevance and deceptive capability. Spear Phishing is an enhanced version of the Phishing attack targeted to a specific user or group. The quality of the targeted email is usually enhanced by appearing to come from a known or trusted entity. If the email account of some trusted entity has been compromised the message may be digitally signed. The message will contain information specific to the targeted users that will enhance the probability that they will follow the URL to the compromised site. For example, the message may indicate knowledge of the targets employment, residence, interests, or other information that suggests familiarity. As soon as the user follows the instructions in the message, the attack proceeds as a standard Phishing attack.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-163 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

social-engineering skill, PWN::Plugins::MailAgent

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-163 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-163`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Obtain useful contextual detailed information about the targeted user or organization] An adversary collects useful contextual detailed information about the targeted user or organization in order to craft a more deceptive and enticing message to lure the target into responding. | techniques: Conduct web searching research of target. See also: CAPEC-118.; Identify trusted assoc…
- Step 2 (Experiment): [Optional: Obtain domain name and certificate to spoof legitimate site] This optional step can be used to help the adversary impersonate the legitimate site more convincingly. The adversary can use homograph attacks to convince users that they are using the legitimate website. Note that this step is not required for phishing attacks, and many phishing attacks simply supply UR…
- Step 3 (Experiment): [Optional: Explore legitimate website and create duplicate] An adversary creates a website (optionally at a URL that looks similar to the original URL) that closely resembles the website that they are trying to impersonate. That website will typically have a login form for the victim to put in their authentication credentials. There can be different variations on a theme here…
- Step 4 (Experiment): [Optional: Build variants of the website with very specific user information e.g., living area, etc.] Once the adversary has their website which duplicates a legitimate website, they need to build very custom user related information in it. For example, they could create multiple variants of the website which would target different living area users by providing information s…
- Step 5 (Exploit): [Convince user to enter sensitive information on adversary's site.] An adversary sends a message (typically an e-mail) to the victim that has some sort of a call to action to get the user to click on the link included in the e-mail (which takes the victim to adversary's website) and log in. The key is to get the victim to believe that the message is coming from a legitimate enti…
- Step 6 (Exploit): [Use stolen credentials to log into legitimate site] Once the adversary captures some sensitive information through phishing (login credentials, credit card information, etc.) the adversary can leverage this information. For instance, the adversary can use the victim's login credentials to log into their bank account and transfer money to an account of their choice. | techniques…

## Prerequisites

- None. Any user can be targeted by a Spear Phishing attack.

## Skills required

- Medium: Spear phishing attacks require specific knowledge of the victims being targeted, such as which bank is being used by the victims, or websites they commonly log into (Google, Facebook, etc).

## Resources required

- An adversay must have the ability communicate their phishing scheme to the victims (via email, instance message, etc.), as well as a website or other platform for victims to enter personal information into.

## Oracles (consequences)

- Confidentiality: Read Data — Information Leakage
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges — Privilege Escalation
- Integrity: Modify Data — Data Modification

## Mitigations to bypass

- Do not follow any links that you receive within your e-mails and certainly do not input any login credentials on the page that they take you too. Instead, call your Bank, PayPal, eBay, etc., and inquire about the problem. A safe practice would also be to type the URL of your bank in the browser directly and only then log in. Also, never reply to any e-mails that ask you to provide sensitive infor…

## Example instances (payload / topology hints)

- The target gets an official looking e-mail from their bank stating that their account has been temporarily locked due to suspected unauthorized activity that happened in a different area from where they live (details might be provided by the spear phishers) and that they need to click on the link included in the e-mail to log in to their bank account in order to unlock it. The link in the e-mail…
- An adversary can leverage a weakness in the SMB protocol by sending the target, an official looking e-mail from their employer's IT Department stating that their system has vulnerable software, which they need to manually patch by accessing an updated version of the software by clicking on a provided link to a network share. Once the link is clicked, the target is directed to an external server c…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-98](CAPEC-98.md)

## Related CWEs (run the cwe skill)

- [CWE-451](../cwe/references/CWE-451.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-163 and CWE IDs
