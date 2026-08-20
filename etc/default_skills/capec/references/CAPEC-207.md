# CAPEC-207: Removing Important Client Functionality

- Catalog: [CAPEC-207](https://capec.mitre.org/data/definitions/207.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary removes or disables functionality on the client that the server assumes to be present and trustworthy.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-207 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-207 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-207`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Probing] The adversary probes, through brute-forcing, reverse-engineering or other similar means, the functionality on the client that server assumes to be present and trustworthy. | techniques: The adversary probes by exploring an application's functionality and its underlying mapping to server-side components.; The adversary reverse engineers client-side code to identify the…
- Step 2 (Experiment): [Determine which functionality to disable or remove] The adversary tries to determine which functionality to disable or remove through reverse-engineering from the list of functionality identified in the Explore phase. | techniques: The adversary reverse engineers the client-side code to determine which functionality to disable or remove.
- Step 3 (Exploit): [Disable or remove the critical functionality from the client code] Once the functionality has been determined, the adversary disables or removes the critical functionality from the client code to perform malicious actions that the server believes are prohibited. | techniques: The adversary disables or removes the functionality from the client-side code to perform malicious acti…

## Prerequisites

- The targeted server must assume the client performs important actions to protect the server or the server functionality. For example, the server may assume the client filters outbound traffic or that the client performs all price calculations correctly. Moreover, the server must fail to detect when these assumptions are violated by a client.

## Skills required

- High: To reverse engineer the client-side code to disable/remove the functionality on the client that the server relies on.
- Low: The adversary installs a web tool that allows scripts or the DOM model of web-based applications to be modified before they are executed in a browser. GreaseMonkey and Firebug are two examples of such tools.

## Resources required

- The adversary must have access to a client and be able to modify the client behavior, often through reverse engineering. If the server is assuming specific client functionality, this usually means the server only recognizes a specific client application, rather than a broad class of client applications. Reverse engineering tools would likely be necessary.

## Oracles (consequences)

- Confidentiality: Other — Information Leakage
- Integrity: Modify Data
- Confidentiality: Read Data
- Accountability, Authentication, Authorization, Non-Repudiation: Gain Privileges
- Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.
- Design: Ship client-side application with integrity checks (code signing) when possible.
- Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

## Example instances (payload / topology hints)

- The adversary reverse engineers a Java binary (by decompiling it) and identifies where license management code exists. Noticing that the license manager returns TRUE or FALSE as to whether or not the user is licensed, the adversary simply overwrites both branch targets to return TRUE, recompiles, and finally redeploys the binary.
- The adversary uses click-through exploration of a Servlet-based website to map out its functionality, taking note of its URL-naming conventions and Servlet mappings. Using this knowledge and guessing the Servlet name of functionality they're not authorized to use, the adversary directly navigates to the privileged functionality around the authorizing single-front controller (implementing programm…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-22](CAPEC-22.md)

## Related CWEs (run the cwe skill)

- [CWE-602](../cwe/references/CWE-602.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-207 and CWE IDs
