# CAPEC-162: Manipulating Hidden Fields

- Catalog: [CAPEC-162](https://capec.mitre.org/data/definitions/162.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits a weakness in the server's trust of client-side processing by modifying data on the client-side, such as price information, and then submitting this data to the server, which processes the modified data. For example, eShoplifting is a data manipulation attack against an on-line merchant during a purchasing transaction. The manipulation of price, discount or quantity fields in the transaction message allows the adversary to acquire items at a lower cost than the merchant intended. The adversary performs a normal purchasing transaction but edits hidden fields within the HTML form response that store price or other information to give themselves a better deal. The merchant then uses the modified pricing information in calculating the cost of the selected items.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-162 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-162 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-162`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Probe target web application] The adversary first probes the target web application to find all possible pages that can be visited on the website. | techniques: Use a spidering tool to follow and record all links; Use a proxy tool to record all links visited during a manual traversal of the web application.
- Step 2 (Explore): [Find hidden fields] Once the web application has been traversed, the adversary looks for all hidden HTML fields present in the client-side. | techniques: Use the inspect tool on all modern browsers and filter for the keyword "hidden"; Specifically look for hidden fields inside form elements.
- Step 3 (Experiment): [Send modified hidden fields to server-side] Once the adversary has found hidden fields in the client-side, they will modify the values of these hidden fields one by one and then interact with the web application so that this data is sent to the server-side. The adversary observes the response from the server to determine if the values of each hidden field are being validated.
- Step 4 (Exploit): [Manipulate hidden fields] Once the adversary has determined which hidden fields are not being validated by the server, they will manipulate them to change the normal behavior of the web application in a way that benefits the adversary. | techniques: Manipulate a hidden field inside a form element and then submit the form so that the manipulated data is sent to the server.

## Prerequisites

- The targeted site must contain hidden fields to be modified.
- The targeted site must not validate the hidden fields with backend processing.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- The adversary must have the ability to modify hidden fields by editing the HTTP response to the server.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-77](CAPEC-77.md)

## Related CWEs (run the cwe skill)

- [CWE-602](../cwe/references/CWE-602.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-162 and CWE IDs
