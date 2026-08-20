# CAPEC-229: Serialized Data Parameter Blowup

- Catalog: [CAPEC-229](https://capec.mitre.org/data/definitions/229.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

This attack exploits certain serialized data parsers (e.g., XML, YAML, etc.) which manage data in an inefficient manner. The attacker crafts an serialized data file with multiple configuration parameters in the same dataset. In a vulnerable parser, this results in a denial of service condition where CPU resources are exhausted because of the parsing algorithm. The weakness being exploited is tied to parser implementation and not language specific.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-229 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::OpenAPI, crafted XML via RestClient / TransparentBrowser

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-229 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-229`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey the target] Using a browser or an automated tool, an attacker records all instances of web services to process requests using serialized data. | techniques: Use an automated tool to record all instances of URLs to process requests from serialized data.; Use a browser to manually explore the website and analyze how the application processes requests using serialized data.
- Step 2 (Exploit): [Launch a Blowup attack] The attacker crafts malicious messages that contain multiple configuration parameters in the same dataset. | techniques: Send the malicious crafted message containing the multiple configuration parameters to the target URL, causing a denial of service.

## Prerequisites

- The server accepts input in the form of serialized data and is using a parser with a runtime longer than O(n) for the insertion of a new configuration parameter in the data container.(examples are .NET framework 1.0 and 1.1)

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- This attack may be mitigated completely by using a parser that is not using a vulnerable container.
- Mitigation may limit the number of configuration parameters per dataset.

## Example instances (payload / topology hints)

- In this example, assume that the victim is running a vulnerable parser such as .NET framework 1.0. This results in a quadratic runtime of O(n^2). <?xml version="1.0"?> <foo aaa="" ZZZ="" ... 999="" /> A document with n attributes results in (n^2)/2 operations to be performed. If an operation takes 100 nanoseconds then a document with 100,000 operations would take 500s to process. In this fashion…
- A YAML bomb leverages references within a YAML file to create exponential growth in memory requirements. By creating a chain of keys whose values are a list of multiple references to the next key in the chain, the amount of memory and processing required to handle the data grows exponentially. This may lead to denial of service or instability resulting from excessive resource consumption.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-231](CAPEC-231.md)

## Related CWEs (run the cwe skill)

- [CWE-770](../cwe/references/CWE-770.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-229 and CWE IDs
