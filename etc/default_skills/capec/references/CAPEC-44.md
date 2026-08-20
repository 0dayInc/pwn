# CAPEC-44: Overflow Binary Resource File

- Catalog: [CAPEC-44](https://capec.mitre.org/data/definitions/44.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An attack of this type exploits a buffer overflow vulnerability in the handling of binary resources. Binary resources may include music files like MP3, image files like JPEG files, and any other binary file. These attacks may pass unnoticed to the client machine through normal usage of files, such as a browser loading a seemingly innocent JPEG file. This can allow the adversary access to the execution stack and execute arbitrary code in the target process.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-44 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST BannedFunctionCallsC / UseAfterFree, PWN::Plugins::Assembly

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-44 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-44`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify target software] The adversary identifies software that uses external binary files in some way. This could be a file upload, downloading a file from a shared location, or other means.
- Step 2 (Experiment): [Find injection vector] The adversary creates a malicious binary file by altering the header to make the file seem shorter than it is. Additional bytes are added to the end of the file to be placed in the overflowed location. The adversary then deploys the file to the software to determine if a buffer overflow was successful.
- Step 3 (Experiment): [Craft overflow content] Once the adversary has determined that this attack is viable, they will specially craft the binary file in a way that achieves the desired behavior. If the source code is available, the adversary can carefully craft the malicious file so that the return address is overwritten to an intended value. If the source code is not available, the adversary wil…
- Step 4 (Exploit): [Overflow the buffer] Once the adversary has constructed a file that will effectively overflow the targeted software in the intended way. The file is deployed to the software, either by serving it directly to the software or placing it in a shared location for a victim to load into the software.

## Prerequisites

- Target software processes binary resource files.
- Target software contains a buffer overflow vulnerability reachable through input from a user-controllable binary resource file.

## Skills required

- Medium: To modify file, deceive client into downloading, locate and exploit remote stack or heap vulnerability

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Availability: Unreliable Execution
- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code

## Mitigations to bypass

- Perform appropriate bounds checking on all buffers.
- Design: Enforce principle of least privilege
- Design: Static code analysis
- Implementation: Execute program in less trusted process space environment, do not allow lower integrity processes to write to higher integrity processes
- Implementation: Keep software patched to ensure that known vulnerabilities are not available for adversaries to target on host.

## Example instances (payload / topology hints)

- Binary files like music and video files are appended with additional data to cause buffer overflow on target systems. Because these files may be filled with otherwise popular content, the adversary has an excellent vector for wide distribution. There have been numerous cases, for example of malicious screen savers for sports teams that are distributed on the event of the team winning a championsh…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-100](CAPEC-100.md)
- ChildOf → [CAPEC-23](CAPEC-23.md)

## Related CWEs (run the cwe skill)

- [CWE-120](../cwe/references/CWE-120.md) — run that CWE procedure after this CAPEC flow
- [CWE-119](../cwe/references/CWE-119.md) — run that CWE procedure after this CAPEC flow
- [CWE-697](../cwe/references/CWE-697.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-44 and CWE IDs
