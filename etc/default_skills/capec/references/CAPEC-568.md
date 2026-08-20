# CAPEC-568: Capture Credentials via Keylogger

- Catalog: [CAPEC-568](https://capec.mitre.org/data/definitions/568.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary deploys a keylogger in an effort to obtain credentials directly from a system's user. After capturing all the keystrokes made by a user, the adversary can analyze the data and determine which string are likely to be passwords or other credential related information.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-568 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-568 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-568`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine which user's credentials to capture] Since this is a more targeted attack, an adversary will first identify a particular user they wish the capture the credentials of.
- Step 2 (Experiment): [Deploy keylogger] Once a user is identified, an adversary will deploy a keylogger to the user's system in one of many ways. | techniques: Send a phishing email with a malicious attachment that installs a keylogger on a user's system; Conceal a keylogger behind fake software and get the user to download the software; Get a user to click on a malicious URL that directs them to…
- Step 3 (Experiment): [Record keystrokes] Once the keylogger is deployed on the user's system, the adversary will record keystrokes over a period of time.
- Step 4 (Experiment): [Analyze data and determine credentials] Using the captured keystrokes, the adversary will be able to determine the credentials of the user. | techniques: Search for repeated sequences that are following by the enter key; Search for repeated sequences that are not found in a dictionary; Search for several backspaces in a row. This could indicate a mistyped password. The corre…
- Step 5 (Exploit): [Use found credentials] After the adversary has found the credentials for the target user, they will then use them to gain access to a system in order to perform some follow-up attack

## Prerequisites

- The ability to install the keylogger, either in person or remote.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Strong physical security can help reduce the ability of an adversary to install a keylogger.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-569](CAPEC-569.md)
- CanPrecede → [CAPEC-600](CAPEC-600.md)
- CanPrecede → [CAPEC-151](CAPEC-151.md)
- CanPrecede → [CAPEC-560](CAPEC-560.md)
- CanPrecede → [CAPEC-561](CAPEC-561.md)
- CanPrecede → [CAPEC-653](CAPEC-653.md)

## Related CWEs (run the cwe skill)

- (none listed in CAPEC catalog)

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-568 and CWE IDs
