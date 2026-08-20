# CAPEC-98: Phishing

- Catalog: [CAPEC-98](https://capec.mitre.org/data/definitions/98.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

Phishing is a social engineering technique where an attacker masquerades as a legitimate entity with which the victim might do business in order to prompt the user to reveal some confidential information (very frequently authentication credentials) that can later be used by an attacker. Phishing is essentially a form of information gathering or "fishing" for information.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-98 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell; social-engineering skill, PWN::Plugins::MailAgent; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-98 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-98`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Obtain domain name and certificate to spoof legitimate site] This optional step can be used to help the attacker impersonate the legitimate site more convincingly. The attacker can use homograph attacks to convince users that they are using the legitimate website. Note that this step is not required for phishing attacks, and many phishing attacks simply supply URLs containing a…
- Step 2 (Explore): [Explore legitimate website and create duplicate] An attacker creates a website (optionally at a URL that looks similar to the original URL) that closely resembles the website that they are trying to impersonate. That website will typically have a login form for the victim to put in their authentication credentials. There can be different variations on a theme here. | techniques…
- Step 3 (Exploit): [Convince user to enter sensitive information on attacker's site.] An attacker sends an e-mail to the victim that has some sort of a call to action to get the user to click on the link included in the e-mail (which takes the victim to attacker's website) and log in. The key is to get the victim to believe that the e-mail is coming from a legitimate entity with which the victim d…
- Step 4 (Exploit): [Use stolen credentials to log into legitimate site] Once the attacker captures some sensitive information through phishing (login credentials, credit card information, etc.) the attacker can leverage this information. For instance, the attacker can use the victim's login credentials to log into their bank account and transfer money to an account of their choice. | techniques: L…

## Prerequisites

- An attacker needs to have a way to initiate contact with the victim. Typically that will happen through e-mail.
- An attacker needs to correctly guess the entity with which the victim does business and impersonate it. Most of the time phishers just use the most popular banks/services and send out their "hooks" to many potential victims.
- An attacker needs to have a sufficiently compelling call to action to prompt the user to take action.
- The replicated website needs to look extremely similar to the original website and the URL used to get to that website needs to look like the real URL of the said business entity.

## Skills required

- Medium: Basic knowledge about websites: obtaining them, designing and implementing them, etc.

## Resources required

- Some web development tools to put up a fake website.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges
- Confidentiality: Read Data
- Integrity: Modify Data

## Mitigations to bypass

- Do not follow any links that you receive within your e-mails and certainly do not input any login credentials on the page that they take you too. Instead, call your Bank, PayPal, eBay, etc., and inquire about the problem. A safe practice would also be to type the URL of your bank in the browser directly and only then log in. Also, never reply to any e-mails that ask you to provide sensitive infor…

## Example instances (payload / topology hints)

- The target gets an official looking e-mail from their bank stating that their account has been temporarily locked due to suspected unauthorized activity and that they need to click on the link included in the e-mail to log in to their bank account in order to unlock it. The link in the e-mail looks very similar to that of their bank and once the link is clicked, the log in page is the exact repli…
- An adversary may use BlueJacking, or Bluetooth Phishing to send unsolicited contact cards, messages, or pictures to nearby devices that are listening via Bluetooth. These messages may contain phishing content.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-151](CAPEC-151.md)
- CanPrecede → [CAPEC-89](CAPEC-89.md)
- CanPrecede → [CAPEC-543](CAPEC-543.md)
- CanPrecede → [CAPEC-611](CAPEC-611.md)
- CanPrecede → [CAPEC-630](CAPEC-630.md)
- CanPrecede → [CAPEC-631](CAPEC-631.md)
- CanPrecede → [CAPEC-632](CAPEC-632.md)

## Related CWEs (run the cwe skill)

- [CWE-451](../cwe/references/CWE-451.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-98 and CWE IDs
