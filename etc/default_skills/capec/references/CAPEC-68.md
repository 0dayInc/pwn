# CAPEC-68: Subvert Code-signing Facilities

- Catalog: [CAPEC-68](https://capec.mitre.org/data/definitions/68.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Low · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

Many languages use code signing facilities to vouch for code's identity and to thus tie code to its assigned privileges within an environment. Subverting this mechanism can be instrumental in an attacker escalating privilege. Any means of subverting the way that a virtual machine enforces code signing classifies for this style of attack.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-68 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-68 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-68`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- A framework-based language that supports code signing (such as, and most commonly, Java or .NET)
- Deployed code that has been signed by its authoring vendor, or a partner.
- The attacker will, for most circumstances, also need to be able to place code in the victim container. This does not necessarily mean that they will have to subvert host-level security, except when explicitly indicated.

## Skills required

- High: Subverting code signing is not a trivial activity. Most code signing and verification schemes are based on use of cryptography and the attacker needs to have an understanding of these cryptographic operations in good detail. Additionally the attacker also needs to be aware of the way memory is assi…

## Resources required

- The Attacker needs no special resources beyond the listed prerequisites in order to conduct this style of attack.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- A given code signing scheme may be fallible due to improper use of cryptography. Developers must never roll out their own cryptography, nor should existing primitives be modified or ignored.
- If an attacker cannot attack the scheme directly, they might try to alter the environment that affects the signing and verification processes. A possible mitigation is to avoid reliance on flags or environment variables that are user-controllable.

## Example instances (payload / topology hints)

- In old versions (prior to 3.0b4) of the Netscape web browser Attackers able to foist a malicious Applet into a client's browser could execute the "Magic Coat" attack. In this attack, the offending Applet would implement its own getSigners() method. This implementation would use the containing VM's APIs to acquire other Applet's signatures (by calling _their_ getSigners() method) and if any runnin…
- Some (older) web browsers allowed scripting languages, such as JavaScript, to call signed Java code. In these circumstances, the browser's VM implementation would choose not to conduct stack inspection across language boundaries (from called signed Java to calling JavaScript) and would short-circuit "true" at the language boundary. Doing so meant that the VM would allow any (unprivileged) script…
- The ability to load unsigned code into the kernel of earlier versions of Vista and bypass integrity checking is an example of such subversion. In the proof-of-concept, it is possible to bypass the signature-checking mechanism Vista uses to load device drivers.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-233](CAPEC-233.md)

## Related CWEs (run the cwe skill)

- [CWE-325](../cwe/references/CWE-325.md) — run that CWE procedure after this CAPEC flow
- [CWE-328](../cwe/references/CWE-328.md) — run that CWE procedure after this CAPEC flow
- [CWE-1326](../cwe/references/CWE-1326.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-68 and CWE IDs
