# CAPEC-656: Voice Phishing

- Catalog: [CAPEC-656](https://capec.mitre.org/data/definitions/656.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary targets users with a phishing attack for the purpose of soliciting account passwords or sensitive information from the user. Voice Phishing is a variation of the Phishing social engineering technique where the attack is initiated via a voice call, rather than email. The user is enticed to provide sensitive information by the adversary, who masquerades as a legitimate employee of the alleged organization. Voice Phishing attacks deviate from standard Phishing attacks, in that a user doesn't typically interact with a compromised website to provide sensitive information and instead provides this information verbally. Voice Phishing attacks can also be initiated by either the adversary in the form of a "cold call" or by the victim if calling an illegitimate telephone number.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-656 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

social-engineering skill, PWN::Plugins::MailAgent

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-656 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-656`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Obtain domain name and certificate to spoof legitimate site] This optional step can be used to help the adversary impersonate the legitimate organization more convincingly. The adversary can use homograph or similar attacks to convince users that they are using the legitimate website. If the adversary leverages cold-calling for this attack, this step is skipped. | techniques: O…
- Step 2 (Explore): [Explore legitimate website and create duplicate] An adversary optionally creates a website (optionally at a URL that looks similar to the original URL) that closely resembles the organization's website that they are trying to impersonate. That website will contain a telephone number for the victim to call to assist them with their issue and initiate the attack. If the adversary…
- Step 3 (Exploit): [Convince user to provide sensitive information to the adversary.] An adversary "cold calls" the victim or receives a call from the victim via the malicious site and provides a call-to-action, in order to persuade the user into providing sensitive details to the adversary (e.g. login credentials, bank account information, etc.). The key is to get the victim to believe that the i…
- Step 4 (Exploit): [Use stolen information] Once the adversary obtains the sensitive information, this information can be leveraged to log into the victim's bank account and transfer money to an account of their choice, or to make fraudulent purchases with stolen credit card information. | techniques: Login to the legitimate site using another the victim's supplied credentials

## Prerequisites

- An adversary needs phone numbers to initiate contact with the victim, in addition to a legitimate-looking telephone number to call the victim from.
- An adversary needs to correctly guess the entity with which the victim does business and impersonate it. Most of the time phishers just use the most popular banks/services and send out their "hooks" to many potential victims.
- An adversary needs to have a sufficiently compelling call to action to prompt the user to take action.
- If passively conducting this attack via a spoofed website, replicated website needs to look extremely similar to the original website and the URL used to get to that website needs to look like the real URL of the said business entity.

## Skills required

- Medium: Basic knowledge about websites: obtaining them, designing and implementing them, etc.

## Resources required

- Legitimate-looking telephone number(s) to initiate calls with victims

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Do not accept calls from unknown numbers or from numbers that may be flagged as spam. Also, do not call numbers that appear on-screen after being unexpectedly redirected to potentially malicious websites. In either case, do not provide sensitive information over voice calls that are not legitimately initiated. Instead, call your Bank, PayPal, eBay, etc., via the number on their public-facing webs…

## Example instances (payload / topology hints)

- The target receives an email or text message stating that their Apple ID has been disabled due to suspicious activity and that the included link includes instructions on how to unlock their Apple account. The link in the text message looks legitimate and once the link is clicked, the user is redirected to a legitimate-looking webpage that prompts the user to call a specified number to initiate th…
- An adversary calls the target and claims to work for their bank. The adversary informs the target that their bank account has been frozen, due to potential fraudulent spending, and requires authentication in order to re-enable the account. The target, believing the caller is a legitimate bank employee, provides their bank account login credentials to confirm they are the authorized owner of the a…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-98](CAPEC-98.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-656 and CWE IDs
