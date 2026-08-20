# CAPEC-667: Bluetooth Impersonation AttackS (BIAS)

- Catalog: [CAPEC-667](https://capec.mitre.org/data/definitions/667.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary disguises the MAC address of their Bluetooth enabled device to one for which there exists an active and trusted connection and authenticates successfully. The adversary can then perform malicious actions on the target Bluetooth device depending on the target’s capabilities.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-667 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-667 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-667`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Find disguise and target] The adversary starts the Bluetooth service on the attacking device and searches for nearby listening devices. | techniques: Knowledge of a trusted MAC address.; Scanning for devices other than the target that may be trusted.
- Step 2 (Experiment): [Disguise] Using the MAC address of the device the adversary wants to impersonate, they may use a tool such as spooftooth or macchanger to spoof their Bluetooth address and attempt to authenticate with the target.
- Step 3 (Exploit): [Use device capabilities to accomplish goal] Finally, if authenticated successfully the adversary can perform tasks/information gathering dependent on the target's capabilities and connections.

## Prerequisites

- Knowledge of a target device's list of trusted connections.

## Skills required

- Low: Adversaries must be capable of using command line Linux tools.
- Low: Adversaries must be in close proximity to Bluetooth devices.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: — An adversary will be impersonating another Bluetooth device, and may gain access to information pertaining to that user along with the ability to manipulate other information.
- Confidentiality: — An adversary will have unauthorized access to information.

## Mitigations to bypass

- Disable Bluetooth in public places.
- Verify incoming Bluetooth connections; do not automatically trust.
- Change default PIN passwords and always use one when connecting.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-616](CAPEC-616.md)

## Related CWEs (run the cwe skill)

- [CWE-290](../cwe/references/CWE-290.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-667 and CWE IDs
