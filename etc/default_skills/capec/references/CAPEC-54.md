# CAPEC-54: Query System for Information

- Catalog: [CAPEC-54](https://capec.mitre.org/data/definitions/54.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Low
- CAPEC list: 3.9

## Attack pattern

An adversary, aware of an application's location (and possibly authorized to use the application), probes an application's structure and evaluates its robustness by submitting requests and examining responses. Often, this is accomplished by sending variants of expected queries in the hope that these modified queries might return information beyond what the expected set of queries would provide.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-54 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-54 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-54`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine parameters] Determine all user-controllable parameters of the application either by probing or by finding documentation
- Step 2 (Experiment): [Cause error condition] Inject each parameter with content that causes an error condition to manifest
- Step 3 (Experiment): [Modify parameters] Modify the content of each parameter according to observed error conditions
- Step 4 (Exploit): [Follow up attack] Once the above steps have been repeated with enough parameters, the application will be sufficiently mapped out. The adversary can then launch a desired attack (for example, Blind SQL Injection)

## Prerequisites

- This class of attacks does not strictly require authorized access to the application. As Attackers use this attack process to classify, map, and identify vulnerable aspects of an application, it simply requires hypotheses to be verified, interaction with the application, and time to conduct trial-and-error activities.

## Skills required

- Medium: Although fuzzing parameters is not difficult, and often possible with automated fuzzers, interpreting the error conditions and modifying the parameters so as to move further in the process of mapping the application requires detailed knowledge of target platform, the languages and packages used as…

## Resources required

- The Attacker needs the ability to probe application functionality and provide it erroneous directives or data without triggering intrusion detection schemes or making enough of an impact on application logging that steps are taken against the adversary. The Attack does not need special hardware, software, skills, or access.

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- Application designers can construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are cataloged and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/log…
- Application designers can wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.

## Example instances (payload / topology hints)

- Blind SQL injection is an example of this technique, applied to successful exploit. See also: CVE-2006-4705
- Attacker sends bad data at various servlets in a J2EE system, records returned exception stack traces, and maps application functionality. In addition, this technique allows attackers to correlate those servlets used with the underlying open source packages (and potentially version numbers) that provide them.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-116](CAPEC-116.md)

## Related CWEs (run the cwe skill)

- [CWE-209](../cwe/references/CWE-209.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-54 and CWE IDs
