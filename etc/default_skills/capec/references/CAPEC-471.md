# CAPEC-471: Search Order Hijacking

- Catalog: [CAPEC-471](https://capec.mitre.org/data/definitions/471.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary exploits a weakness in an application's specification of external libraries to exploit the functionality of the loader where the process loading the library searches first in the same directory in which the process binary resides and then in other directories. Exploitation of this preferential search order can allow an attacker to make the loading process load the adversary's rogue library rather than the legitimate library. This attack can be leveraged with many different libraries and with many different loading processes. No forensic trails are left in the system's registry or file system that an incorrect library had been loaded.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-471 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-471 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-471`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target general susceptibility] An attacker uses an automated tool or manually finds whether the target application uses dynamically linked libraries and the configuration file or look up table (such as Procedure Linkage Table) which contains the entries for dynamically linked libraries. | techniques: The attacker uses a tool such as the OSX "otool" utility or manually…
- Step 2 (Experiment): [Craft malicious libraries] The attacker uses knowledge gained in the Explore phase to craft malicious libraries that they will redirect the target to leverage. These malicious libraries could have the same APIs as the legitimate library and additional malicious code. | techniques: The attacker monitors the file operations performed by the target application using a tool like…
- Step 3 (Exploit): [Redirect the access to libraries to the malicious libraries] The attacker redirects the target to the malicious libraries they crafted in the Experiment phase. The attacker will be able to force the targeted application to execute arbitrary code when the application attempts to access the legitimate libraries. | techniques: The attacker modifies the entries in the configuration…

## Prerequisites

- Attacker has a mechanism to place its malicious libraries in the needed location on the file system.

## Skills required

- Medium: Ability to create a malicious library.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Design: Fix the Windows loading process to eliminate the preferential search order by looking for DLLs in the precise location where they are expected
- Design: Sign system DLLs so that unauthorized DLLs can be detected.

## Example instances (payload / topology hints)

- For instance, an attacker with access to the file system may place a malicious ntshrui.dll in the C:\Windows directory. This DLL normally resides in the System32 folder. Process explorer.exe which also resides in C:\Windows, upon trying to load the ntshrui.dll from the System32 folder will actually load the DLL supplied by the attacker simply because of the preferential search order. Since the at…
- macOS and OS X use a common method to look for required dynamic libraries (dylib) to load into a program based on search paths. Adversaries can take advantage of ambiguous paths to plant dylibs to gain privilege escalation or persistence. A common method is to see what dylibs an application uses, then plant a malicious version with the same name higher up in the search path. This typically result…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-159](CAPEC-159.md)

## Related CWEs (run the cwe skill)

- [CWE-427](../cwe/references/CWE-427.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-471 and CWE IDs
