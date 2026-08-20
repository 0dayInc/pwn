# CAPEC-217: Exploiting Incorrectly Configured SSL/TLS

- Catalog: [CAPEC-217](https://capec.mitre.org/data/definitions/217.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Low · Typical severity: not stated
- CAPEC list: 3.9

## Attack pattern

An adversary takes advantage of incorrectly configured SSL/TLS communications that enables access to data intended to be encrypted. The adversary may also use this type of attack to inject commands or other traffic into the encrypted stream to cause compromise of either the client or server.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-217 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-217 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-217`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine SSL/TLS Configuration] Determine the SSL/TLS configuration of either the server or client being targeted, preferably both. This is not a hard requirement, as the adversary can simply assume commonly exploitable configuration settings and indiscriminately attempt them. | techniques: If the target is a webpage, some of the SSL/TLS configuration can be viewed through the…
- Step 2 (Experiment): [Intercept Communication] Provide controlled access to the server by the client, by either providing a link for the client to click on, or by positioning one's self at a place on the network to intercept and control the flow of data between client and server, e.g. AiTM (adversary in the middle - CAPEC-94). | techniques: Create a malicious webpage that looks identical to the t…
- Step 3 (Exploit): [Capture or Manipulate Sensitive Data] Once the adversary has the ability to intercept the secure communication, they exploit the incorrectly configured SSL to view the encrypted communication. The adversary can choose to just record the secure communication or manipulate the data to achieve a desired effect. | techniques: Use known exploits for old SSL and TLS versions.; Use kn…

## Prerequisites

- Access to the client/server stream.

## Skills required

- High: The adversary needs real-time access to network traffic in such a manner that the adversary can grab needed information from the SSL stream, possibly influence the decided-upon encryption method and options, and perform automated analysis to decipher encrypted material recovered. Tools exist to aut…

## Resources required

- The adversary needs the ability to sniff traffic, and optionally be able to route said traffic to a system where the sniffing of traffic can take place, and act upon the recovered traffic in real time.

## Oracles (consequences)

- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Do not use SSL, as all SSL versions have been broken and should not be used. If TLS is not an option for the client or server, consider setting timeouts on SSL sessions to extremely low values to lessen the potential impact.
- Only use TLS version 1.2+, as versions 1.0 and 1.1 are insecure.
- Configure TLS to use secure algorithms. The current recommendation is to use ECDH, ECDSA, AES256-GCM, and SHA384 for the most security.

## Example instances (payload / topology hints)

- Using MITM techniques, an adversary launches a blockwise chosen-boundary attack to obtain plaintext HTTP headers by taking advantage of an SSL session using an encryption protocol in CBC mode with chained initialization vectors (IV). This allows the adversary to recover session IDs, authentication cookies, and possibly other valuable data that can be used for further exploitation. Additionally th…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-216](CAPEC-216.md)

## Related CWEs (run the cwe skill)

- [CWE-201](../cwe/references/CWE-201.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-217 and CWE IDs
