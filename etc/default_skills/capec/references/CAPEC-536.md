# CAPEC-536: Data Injected During Configuration

- Catalog: [CAPEC-536](https://capec.mitre.org/data/definitions/536.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: Low · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker with access to data files and processes on a victim's system injects malicious data into critical operational data during configuration or recalibration, causing the victim's system to perform in a suboptimal manner that benefits the adversary.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-536 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-536 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-536`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine configuration process] The adversary, through a previously compromised system, either remotely or physically, determines what the configuration process is. They look at configuration files, data files, and running processes on the system to identify areas where they could inject malicious data.
- Step 2 (Explore): [Determine when configuration occurs] The adversary needs to then determine when configuration or recalibration of a system occurs so they know when to inject malicious data. | techniques: Look for a weekly update cycle or repeated update schedule.; Insert a malicious process into the target system that notifies the adversary when configuration is occurring.
- Step 3 (Experiment): [Determine malicious data to inject] By looking at the configuration process, the adversary needs to determine what malicious data they want to insert and where to insert it. | techniques: Add false log data; Change configuration files; Change data files
- Step 4 (Exploit): [Inject malicious data] Right before, or during system configuration, the adversary injects the malicious data. This leads to the system behaving in a way that is beneficial to the adversary and is often followed by other attacks.

## Prerequisites

- The attacker must have previously compromised the victim's systems or have physical access to the victim's systems.
- Advanced knowledge of software and hardware capabilities of a manufacturer's product.

## Skills required

- High: Ability to generate and inject false data into operational data into a system with the intent of causing the victim to alter the configuration of the system.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Ensure that proper access control is implemented on all systems to prevent unauthorized access to system files and processes.

## Example instances (payload / topology hints)

- An adversary wishes to bypass a security system to access an additional network segment where critical data is kept. The adversary knows that some configurations of the security system will allow for remote bypass under certain conditions, such as switching a specific parameter to a different value. The adversary knows the bypass will work but also will be detected within the logging data of the…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-176](CAPEC-176.md)

## Related CWEs (run the cwe skill)

- [CWE-284](../cwe/references/CWE-284.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-536 and CWE IDs
