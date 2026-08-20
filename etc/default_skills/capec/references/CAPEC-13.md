# CAPEC-13: Subverting Environment Variable Values

- Catalog: [CAPEC-13](https://capec.mitre.org/data/definitions/13.html)
- Abstraction: Detailed · Status: Stable
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

The adversary directly or indirectly modifies environment variables used by or controlling the target software. The adversary's goal is to cause the target software to deviate from its expected operation in a manner that benefits the adversary.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-13 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-13 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-13`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Probe target application] The adversary first probes the target application to determine important information about the target. This information could include types software used, software versions, what user input the application consumes, and so on. Most importantly, the adversary tries to determine what environment variables might be used by the underlying software, or even…
- Step 2 (Experiment): [Find user-controlled environment variables] Using the information found by probing the application, the adversary attempts to manipulate any user-controlled environment variables they have found are being used by the application, or suspect are being used by the application, and observe the effects of these changes. If the adversary notices any significant changes to the app…
- Step 3 (Exploit): [Manipulate user-controlled environment variables] The adversary manipulates the found environment variable(s) to abuse the normal flow of processes or to gain access to privileged resources.

## Prerequisites

- An environment variable is accessible to the user.
- An environment variable used by the application can be tainted with user supplied data.
- Input data used in an environment variable is not validated properly.
- The variables encapsulation is not done properly. For instance setting a variable as public in a class makes it visible and an adversary may attempt to manipulate that variable.

## Skills required

- Low: In a web based scenario, the client controls the data that it submitted to the server. So anybody can try to send malicious data and try to bypass the authentication mechanism.
- High: Some more advanced attacks may require knowledge about protocols and probing technique which help controlling a variable. The malicious user may try to understand the authentication mechanism in order to defeat it.

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Confidentiality, Integrity, Availability: Execute Unauthorized Commands — Run Arbitrary Code
- Confidentiality, Access Control, Authorization: Bypass Protection Mechanism
- Availability: Unreliable Execution
- Confidentiality: Read Data
- Accountability: Hide Activities

## Mitigations to bypass

- Protect environment variables against unauthorized read and write access.
- Protect the configuration files which contain environment variables against illegitimate read and write access.
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system.
- Apply the least privilege principles. If a process has no legitimate reason to read an environment variable do not give that privilege.

## Example instances (payload / topology hints)

- Changing the LD_LIBRARY_PATH environment variable in TELNET will cause TELNET to use an alternate (possibly Trojan) version of a function library. The Trojan library must be accessible using the target file system and should include Trojan code that will allow the user to log in with a bad password. This requires that the adversary upload the Trojan library to a specific location on the target. A…
- The HISTCONTROL environment variable keeps track of what should be saved by the history command and eventually into the ~/.bash_history file when a user logs out. This setting can be configured to ignore commands that start with a space by simply setting it to "ignorespace". HISTCONTROL can also be set to ignore duplicate commands by setting it to "ignoredups". In some Linux systems, this is set…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-77](CAPEC-77.md)
- CanPrecede → [CAPEC-14](CAPEC-14.md)
- PeerOf → [CAPEC-10](CAPEC-10.md)

## Related CWEs (run the cwe skill)

- [CWE-353](../cwe/references/CWE-353.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-302](../cwe/references/CWE-302.md) — run that CWE procedure after this CAPEC flow
- [CWE-74](../cwe/references/CWE-74.md) — run that CWE procedure after this CAPEC flow
- [CWE-15](../cwe/references/CWE-15.md) — run that CWE procedure after this CAPEC flow
- [CWE-73](../cwe/references/CWE-73.md) — run that CWE procedure after this CAPEC flow
- [CWE-20](../cwe/references/CWE-20.md) — run that CWE procedure after this CAPEC flow
- [CWE-200](../cwe/references/CWE-200.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-13 and CWE IDs
