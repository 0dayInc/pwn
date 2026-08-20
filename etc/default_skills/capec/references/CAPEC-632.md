# CAPEC-632: Homograph Attack via Homoglyphs

- Catalog: [CAPEC-632](https://capec.mitre.org/data/definitions/632.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Low · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary registers a domain name containing a homoglyph, leading the registered domain to appear the same as a trusted domain. A homograph attack leverages the fact that different characters among various character sets look the same to the user. Homograph attacks must generally be combined with other attacks, such as phishing attacks, in order to direct Internet traffic to the adversary-controlled destinations.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-632 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

social-engineering skill, PWN::Plugins::MailAgent

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-632 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-632`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine target website] The adversary first determines which website to impersonate, generally one that is trusted and receives a consistent amount of traffic. | techniques: Research popular or high traffic websites.
- Step 2 (Experiment): [Impersonate trusted domain] In order to impersonate the trusted domain, the adversary needs to register the URL containing the homoglpyh character(s). | techniques: Register the Homograph domain.
- Step 3 (Exploit): [Deceive user into visiting domain] Finally, the adversary needs to deceive a user into visiting the Homograph domain. | techniques: Execute a phishing attack and send a user an e-mail convincing the to click on a link leading the user to the malicious domain.

## Prerequisites

- An adversary requires knowledge of popular or high traffic domains, that could be used to deceive potential targets.

## Skills required

- Low: Adversaries must be able to register DNS hostnames/URL’s.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Other: Other — Depending on the intention of the adversary, a successful Homograph attack can be leveraged to execute more complex attacks such as cross-site scripting or stealing account credentials.

## Mitigations to bypass

- Authenticate all servers and perform redundant checks when using DNS hostnames.
- Utilize browsers that can warn users if URLs contain characters from different character sets.

## Example instances (payload / topology hints)

- An adversary sends an email, impersonating bankofamerica.com to a user stating that they have just received a new deposit and to click the given link to confirm the deposit. However, the link the in email is bankofamerica.com, where the 'a' and 'e' characters are Cyrillic and not ASCII, instead of bankofamerica.com (all ASCII), which the user clicks after carefully reading the URL, making sure th…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-616](CAPEC-616.md)
- CanPrecede → [CAPEC-89](CAPEC-89.md)
- CanPrecede → [CAPEC-543](CAPEC-543.md)

## Related CWEs (run the cwe skill)

- [CWE-1007](../cwe/references/CWE-1007.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-632 and CWE IDs
