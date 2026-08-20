# CAPEC-174: Flash Parameter Injection

- Catalog: [CAPEC-174](https://capec.mitre.org/data/definitions/174.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary takes advantage of improper data validation to inject malicious global parameters into a Flash file embedded within an HTML document. Flash files can leverage user-submitted data to configure the Flash document and access the embedding HTML document.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-174 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-174 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-174`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Spider] Using a browser or an automated tool, an adversary records all instances of HTML documents that have embedded Flash files. If there is an embedded Flash file, they list how to pass global parameters to the Flash file from the embedding object. | techniques: Use an automated tool to record all instances of URLs which have embedded Flash files and list the parameters pass…
- Step 2 (Experiment): [Determine the application susceptibility to Flash parameter injection] Determine the application susceptibility to Flash parameter injection. For each URL identified in the Explore phase, the adversary attempts to use various techniques such as DOM based, reflected, flashvars, and persistent attacks depending on the type of parameter passed to the embedded Flash file. | tech…
- Step 3 (Exploit): [Execute Flash Parameter Injection Attack] Inject parameters into Flash file. Based on the results of the Experiment phase, the adversary crafts the underlying malicious URL containing injected Flash parameters and submits it to the web server. Once the web server receives the request, the embedding HTML document will controllable by the adversary. | techniques: Craft underlying…

## Prerequisites

- (none listed in CAPEC catalog)

## Skills required

- Medium: The adversary need inject values into the global parameters to the Flash file and understand the parent HTML document DOM structure. The adversary needs to be smart enough to convince the victim to click on their crafted link.

## Resources required

- The adversary must convince the victim to click their crafted link.

## Oracles (consequences)

- Confidentiality: Other — Information Leakage
- Authorization: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- User input must be sanitized according to context before reflected back to the user. The JavaScript function 'encodeURI' is not always sufficient for sanitizing input intended for global Flash parameters. Extreme caution should be taken when saving user input in Flash cookies. In such cases the Flash file itself will need to be fixed and recompiled, changing the name of the local shared objects (…

## Example instances (payload / topology hints)

- The following are examples for different types of parameters passed to the Flash file. DOM-based Flash parameter injection <object> <embed src="myFlash.swf" flashvars="location=http://example.com/index.htm#&globalVar=e-v-i-l"></embed> </object> Passing parameter in an embedded URI <object type="application/x-shockwave-flash" data="myfile.swf?globalVar=e-v-i-l" ></object> Passing parameter in flas…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-182](CAPEC-182.md)
- CanAlsoBe → [CAPEC-460](CAPEC-460.md)
- CanPrecede → [CAPEC-63](CAPEC-63.md)
- CanPrecede → [CAPEC-178](CAPEC-178.md)

## Related CWEs (run the cwe skill)

- [CWE-88](../cwe/references/CWE-88.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-174 and CWE IDs
