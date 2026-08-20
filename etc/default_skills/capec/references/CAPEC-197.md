# CAPEC-197: Exponential Data Expansion

- Catalog: [CAPEC-197](https://capec.mitre.org/data/definitions/197.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary submits data to a target application which contains nested exponential data expansion to produce excessively large output. Many data format languages allow the definition of macro-like structures that can be used to simplify the creation of complex structures. However, this capability can be abused to create excessive demands on a processor's CPU and memory. A small number of nested expansions can result in an exponential growth in demands on memory.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-197 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-197 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-197`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the target] An adversary determines the input data stream that is being processed by a data parser that supports using subsitituion on the victim's side. | techniques: Use an automated tool to record all instances of URLs to process requests.; Use a browser to manually explore the website and analyze how the application processes requests.
- Step 2 (Experiment): [Craft malicious payload] The adversary crafts a malicious message containing nested exponential expansion that completely uses up available server resources. See the "Example Instances" section for details on how to craft this malicious payload.
- Step 3 (Exploit): [Send the message] Send the malicious crafted message to the target URL.

## Prerequisites

- This type of attack requires that the target must receive input but either fail to provide an upper limit for entity expansion or provide a limit that is so large that it does not preclude significant resource consumption.

## Skills required

- Low: Ability to craft nested data expansion messages.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Availability: Unreliable Execution, Resource Consumption — Denial of Service

## Mitigations to bypass

- Design: Use libraries and templates that minimize unfiltered input. Use methods that limit entity expansion and throw exceptions on attempted entity expansion.
- Implementation: For XML based data - disable altogether the use of inline DTD schemas when parsing XML objects. If a DTD must be used, normalize, filter and use an allowlist and parse with methods and routines that will detect entity expansion from untrusted sources.

## Example instances (payload / topology hints)

- The most common example of this type of attack is the "many laughs" attack (sometimes called the 'billion laughs' attack). For example: <?xml version="1.0"?> <!DOCTYPE lolz [ <!ENTITY lol "lol"> <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"> <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"> <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&…
- This example is similar, but uses YAML. This was used to attack Kubernetes [REF-686] a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"] b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a] c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b] d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c] e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d] f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e] g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f] h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g] i: &i […

## Related CAPECs (test these too)

- ChildOf → [CAPEC-230](CAPEC-230.md)

## Related CWEs (run the cwe skill)

- [CWE-770](../cwe/references/CWE-770.md) — run that CWE procedure after this CAPEC flow
- [CWE-776](../cwe/references/CWE-776.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-197 and CWE IDs
