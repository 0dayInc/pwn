# CAPEC-150: Collect Data from Common Resource Locations

- Catalog: [CAPEC-150](https://capec.mitre.org/data/definitions/150.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: not stated · Typical severity: Medium
- CAPEC list: 3.9

## Attack pattern

An adversary exploits well-known locations for resources for the purposes of undermining the security of the target. In many, if not most systems, files and resources are organized in a default tree structure. This can be useful for adversaries because they often know where to look for resources or files that are necessary for attacks. Even when the precise location of a targeted resource may not be known, naming conventions may indicate a small area of the target machine's file tree where the resources are typically located. For example, configuration files are normally stored in the /etc director on Unix systems. Adversaries can take advantage of this to commit other types of attacks.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-150 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-150 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-150`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- (none listed in CAPEC catalog)

## Prerequisites

- The targeted applications must either expect files to be located at a specific location or, if the location of the files can be configured by the user, the user either failed to move the files from the default location or placed them in a conventional location for files of the given type.

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- None: No specialized resources are required to execute this type of attack. In some cases, the attacker need not even have direct access to the locations on the target computer where the targeted resources reside.

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- (none listed in CAPEC catalog)

## Example instances (payload / topology hints)

- An adversary can use a technique called Bluesnarfing to retrieve data from Bluetooth enabled devices in which they know where the data is located. This is done by connecting to the device’s Object Exchange (OBEX) Push Profile and making OBEX GET requests for known filenames (contact lists, photos, recent calls). Bluesnarfing was patched shortly after its discovery in 2003 and will only work on de…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-116](CAPEC-116.md)

## Related CWEs (run the cwe skill)

- [CWE-552](../cwe/references/CWE-552.md) — run that CWE procedure after this CAPEC flow
- [CWE-1239](../cwe/references/CWE-1239.md) — run that CWE procedure after this CAPEC flow
- [CWE-1258](../cwe/references/CWE-1258.md) — run that CWE procedure after this CAPEC flow
- [CWE-1266](../cwe/references/CWE-1266.md) — run that CWE procedure after this CAPEC flow
- [CWE-1272](../cwe/references/CWE-1272.md) — run that CWE procedure after this CAPEC flow
- [CWE-1323](../cwe/references/CWE-1323.md) — run that CWE procedure after this CAPEC flow
- [CWE-1330](../cwe/references/CWE-1330.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-150 and CWE IDs
