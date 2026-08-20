# CAPEC-39: Manipulating Opaque Client-based Data Tokens

- Catalog: [CAPEC-39](https://capec.mitre.org/data/definitions/39.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

In circumstances where an application holds important data client-side in tokens (cookies, URLs, data files, and so forth) that data can be manipulated. If client or server-side application components reinterpret that data as authentication tokens or data (such as store item pricing or wallet information) then even opaquely manipulating that data may bear fruit for an Attacker. In this pattern an attacker undermines the assumption that client side tokens have been adequately protected from tampering through use of encryption or obfuscation.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-39 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-39 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-39`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Enumerate information passed to client side] The attacker identifies the parameters used as part of tokens to take business or security decisions | techniques: Use WebScarab to reveal hidden fields while browsing.; Use a sniffer to capture packets; View source of web page to find hidden fields; Examine URL to see if any opaque tokens are in it; Disassemble or decompile client-s…
- Step 2 (Explore): [Determine protection mechanism for opaque token] The attacker determines the protection mechanism used to protect the confidentiality and integrity of these data tokens. They may be obfuscated or a full blown encryption may be used. | techniques: Look for signs of well-known character encodings; Look for cryptographic signatures; Look for delimiters or other indicators of struc…
- Step 3 (Experiment): [Modify parameter/token values] Trying each parameter in turn, the attacker modifies the values | techniques: Modify tokens logically; Modify tokens arithmetically; Modify tokens bitwise; Modify structural components of tokens; Modify order of parameters/tokens
- Step 4 (Experiment): [Cycle through values for each parameter.] Depending on the nature of the application, the attacker now cycles through values of each parameter and observes the effects of this modification in the data returned by the server | techniques: Use network-level packet injection tools such as netcat; Use application-level data modification tools such as Tamper Data, WebScarab, Tamp…

## Prerequisites

- An attacker already has some access to the system or can steal the client based data tokens from another user who has access to the system.
- For an Attacker to viably execute this attack, some data (later interpreted by the application) must be held client-side in a way that can be manipulated without detection. This means that the data or tokens are not CRCd as part of their value or through a separate meta-data store elsewhere.

## Skills required

- Medium: If the client site token is obfuscated.
- High: If the client site token is encrypted.

## Resources required

- The Attacker needs no special hardware-based resources in order to conduct this attack. Software plugins, such as Tamper Data for Firefox, may help in manipulating URL- or cookie-based data.

## Oracles (consequences)

- Integrity: Modify Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- One solution to this problem is to protect encrypted data with a CRC of some sort. If knowing who last manipulated the data is important, then using a cryptographic "message authentication code" (or hMAC) is prescribed. However, this guidance is not a panacea. In particular, any value created by (and therefore encrypted by) the client, which itself is a "malicious" value, all the protective crypt…
- Make sure to protect client side authentication tokens for confidentiality (encryption) and integrity (signed hash)
- Make sure that all session tokens use a good source of randomness
- Perform validation on the server side to make sure that client side data tokens are consistent with what is expected.

## Example instances (payload / topology hints)

- With certain price watching websites, that aggregate products available prices, the user can buy items through whichever vendors has product availability, the best price, or other differentiator. Once a user selects an item, the site must broker the purchase of that item with the vendor. Because vendors sell the same product through different channel partners at different prices, token exchange b…
- Upon successful authentication user is granted an encrypted authentication cookie by the server and it is stored on the client. One piece of information stored in the authentication cookie reflects the access level of the user (e.g. "u" for user). The authentication cookie is encrypted using the Electronic Code Book (ECB) mode, that naively encrypts each of the plaintext blocks to each of the cip…
- Archangel Weblog 0.90.02 allows remote attackers to bypass authentication by setting the ba_admin cookie to 1. See also: CVE-2006-0944

## Related CAPECs (test these too)

- ChildOf → [CAPEC-22](CAPEC-22.md)

## Related CWEs (run the cwe skill)

- [CWE-353](../cwe/references/CWE-353.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-302](../cwe/references/CWE-302.md) — run that CWE procedure after this CAPEC flow
- [CWE-472](../cwe/references/CWE-472.md) — run that CWE procedure after this CAPEC flow
- [CWE-565](../cwe/references/CWE-565.md) — run that CWE procedure after this CAPEC flow
- [CWE-315](../cwe/references/CWE-315.md) — run that CWE procedure after this CAPEC flow
- [CWE-539](../cwe/references/CWE-539.md) — run that CWE procedure after this CAPEC flow
- [CWE-384](../cwe/references/CWE-384.md) — run that CWE procedure after this CAPEC flow
- [CWE-233](../cwe/references/CWE-233.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-39 and CWE IDs
