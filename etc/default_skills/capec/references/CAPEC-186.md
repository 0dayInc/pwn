# CAPEC-186: Malicious Software Update

- Catalog: [CAPEC-186](https://capec.mitre.org/data/definitions/186.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: not stated · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary uses deceptive methods to cause a user or an automated process to download and install dangerous code believed to be a valid update that originates from an adversary controlled source.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-186 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-186 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-186`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target] The adversary must first identify what they want their target to be. Because malicious software updates can be carried out in a variety of ways, the adversary will first not only identify a target program, but also what users they wish to target. This attack can be targeted (a particular user or group of users) or untargeted (many different users).
- Step 2 (Experiment): [Craft a deployment mechanism based on the target] The adversary must craft a deployment mechanism to deploy the malicious software update. This mechanism will differ based on if the attack is targeted or untargeted. | techniques: Targeted attack: hosting what appears to be a software update, then harvesting actual email addresses for an organization, or generating commonly u…
- Step 3 (Exploit): [Deploy malicious software update] Using the deployment mechanism from the previous step, the adversary gets a user to install the malicious software update.

## Prerequisites

- (none listed in CAPEC catalog)

## Skills required

- High: This attack requires advanced cyber capabilities

## Resources required

- Manual or user-assisted attacks require deceptive mechanisms to trick the user into clicking a link or downloading and installing software. Automated update attacks require the adversary to host a payload and then trigger the installation of the payload code.

## Oracles (consequences)

- Access Control, Availability, Confidentiality: Execute Unauthorized Commands — Utilize the built-in software update mechanisms of the commercial components to deliver software that could compromise security credentials, enable a denial-of-service attack, or enable tracking.

## Mitigations to bypass

- Validate software updates before installing.

## Example instances (payload / topology hints)

- Using an automated process to download and install dangerous code was key part of the NotPeyta attack [REF-697]

## Related CAPECs (test these too)

- ChildOf → [CAPEC-184](CAPEC-184.md)
- CanFollow → [CAPEC-98](CAPEC-98.md)

## Related CWEs (run the cwe skill)

- [CWE-494](../cwe/references/CWE-494.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-186 and CWE IDs
