# CAPEC-101: Server Side Include (SSI) Injection

- Catalog: [CAPEC-101](https://capec.mitre.org/data/definitions/101.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An attacker can use Server Side Include (SSI) Injection to send code to a web application that then gets executed by the web server. Doing so enables the attacker to achieve similar results to Cross Site Scripting, viz., arbitrary code execution and information disclosure, albeit on a more limited scale, since the SSI directives are nowhere near as powerful as a full-fledged scripting language. Nonetheless, the attacker can conveniently gain access to sensitive files, such as password files, and execute shell commands.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-101 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-101 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-101`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine applicability] The adversary determines whether server side includes are enabled on the target web server. | techniques: Look for popular page file names. The attacker will look for .shtml, .shtm, .asp, .aspx, and other well-known strings in URLs to help determine whether SSI functionality is enabled.; Fetch .htaccess file. In Apache web server installations, the .hta…
- Step 2 (Experiment): [Find Injection Point] Look for user controllable input, including HTTP headers, that can carry server side include directives to the web server. | techniques: Use a spidering tool to follow and record all links. Make special note of any links that include parameters in the URL.; Use a proxy tool to record all links visited during a manual traversal of the web application. Ma…
- Step 3 (Exploit): [Inject SSI] Using the found injection point, the adversary sends arbitrary code to be inlcuded by the application on the server side. They may then need to view a particular page in order to have the server execute the include directive and run a command or open a file on behalf of the adversary.

## Prerequisites

- A web server that supports server side includes and has them enabled
- User controllable input that can carry include directives to the web server

## Skills required

- Medium: The attacker needs to be aware of SSI technology, determine the nature of injection and be able to craft input that results in the SSI directives being executed.

## Resources required

- None: No specialized resources are required to execute this type of attack. Determining whether the server supports SSI does not require special tools, and nor does injecting directives that get executed. Spidering tools can make the task of finding and following links easier.

## Oracles (consequences)

- Confidentiality: Read Data
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them
- All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive
- Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead

## Example instances (payload / topology hints)

- Consider a website hosted on a server that permits Server Side Includes (SSI), such as Apache with the "Options Includes" directive enabled. Whenever an error occurs, the HTTP Headers along with the entire request are logged, which can then be displayed on a page that allows review of such errors. A malicious user can inject SSI directives in the HTTP Headers of a request designed to create an er…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-253](CAPEC-253.md)
- CanPrecede → [CAPEC-600](CAPEC-600.md)

## Related CWEs (run the cwe skill)

- [CWE-97](../cwe/references/CWE-97.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-101 and CWE IDs
