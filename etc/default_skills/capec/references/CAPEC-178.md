# CAPEC-178: Cross-Site Flashing

- Catalog: [CAPEC-178](https://capec.mitre.org/data/definitions/178.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: Medium · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An attacker is able to trick the victim into executing a Flash document that passes commands or calls to a Flash player browser plugin, allowing the attacker to exploit native Flash functionality in the client browser. This attack pattern occurs where an attacker can provide a crafted link to a Flash document (SWF file) which, when followed, will cause additional malicious instructions to be executed. The attacker does not need to serve or control the Flash document. The attack takes advantage of the fact that Flash files can reference external URLs. If variables that serve as URLs that the Flash application references can be controlled through parameters, then by creating a link that includes values for those parameters, an attacker can cause arbitrary content to be referenced and possibly executed by the targeted Flash application.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-178 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-178 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-178`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identification] Using a browser or an automated tool, an attacker records all instances of URLs (or partial URL such as domain) passed to a flash file (SWF). | techniques: Use an automated tool to record the variables passed to a flash file.; Use a browser to manually explore the website and analyze how the flash file receive variables, e.g. JavaScript using SetVariable/GetVari…
- Step 2 (Experiment): [Attempt to inject a remote flash file] The attacker makes use of a remotely available flash file (SWF) that generates a uniquely identifiable output when executed inside the targeted flash file. | techniques: Modify the variable of the SWF file that contains the remote movie URL to the attacker controlled flash file.
- Step 3 (Exploit): [Access or Modify Flash Application Variables] As the attacker succeeds in exploiting the vulnerability, they target the content of the flash application to steal variable content, password, etc. | techniques: Develop malicious Flash application that is injected through vectors identified during the Experiment Phase and loaded by the victim browser's flash plugin and sends docum…
- Step 4 (Exploit): [Execute JavaScript in victim's browser] When the attacker targets the current flash application, they can choose to inject JavaScript in the client's DOM and therefore execute cross-site scripting attack. | techniques: Develop malicious JavaScript that is injected from the rogue flash movie to the targeted flash application through vectors identified during the Experiment Phase…

## Prerequisites

- The targeted Flash application must reference external URLs and the locations thus referenced must be controllable through parameters. The Flash application must fail to sanitize such parameters against malicious manipulation. The victim must follow a crafted link created by the attacker.

## Skills required

- Medium: knowledge of Flash internals, parameters and remote referencing.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality: Read Data
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Implementation: Only allow known URL to be included as remote flash movies in a flash application
- Configuration: Properly configure the crossdomain.xml file to only include the known domains that should host remote flash movies.

## Example instances (payload / topology hints)

- The attacker tries to get their malicious flash movie to be executed in the targeted flash application. The malicious file is hosted on the attacker.com domain and the targeted flash application is hosted on example.com The crossdomain.xml file in the root of example.com allows all domains and no specific restriction is specified in the targeted flash application. When the attacker injects their…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-182](CAPEC-182.md)

## Related CWEs (run the cwe skill)

- [CWE-601](../cwe/references/CWE-601.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-178 and CWE IDs
