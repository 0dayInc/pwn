# CAPEC-159: Redirect Access to Libraries

- Catalog: [CAPEC-159](https://capec.mitre.org/data/definitions/159.html)
- Abstraction: Standard · Status: Stable
- Likelihood of attack: High · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An adversary exploits a weakness in the way an application searches for external libraries to manipulate the execution flow to point to an adversary supplied library or code base. This pattern of attack allows the adversary to compromise the application or server via the execution of unauthorized code. An application typically makes calls to functions that are a part of libraries external to the application. These libraries may be part of the operating system or they may be third party libraries. If an adversary can redirect an application's attempts to access these libraries to other libraries that the adversary supplies, the adversary will be able to force the targeted application to execute arbitrary code. This is especially dangerous if the targeted application has enhanced privileges. Access can be redirected through a number of techniques, including the use of symbolic links, search path modification, and relative path manipulation.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-159 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::TransparentBrowser, PWN::Plugins::URIScheme; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-159 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-159`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify Target] The adversary identifies the target application and determines what libraries are being used. | techniques: Find public source code and identify library dependencies.; Gain access to the system hosting the application and look for libraries in common locations.
- Step 2 (Experiment): [Deploy Malicious Libraries] The adversary crafts malicious libraries and deploys them on the system where the application is running, or in a remote location that can be loaded by the application.
- Step 3 (Exploit): [Redirect Library Calls to Malicious Library] Once the malicious library crafted by the adversary is deployed, the adversary will manipulate the flow of the application such that it calls the malicious library. This can be done in a variety of ways based on how the application is loading and calling libraries. | techniques: Poison the DNS cache of the system so that it loads a m…

## Prerequisites

- The target must utilize external libraries and must fail to verify the integrity of these libraries before using them.

## Skills required

- Low: To modify the entries in the configuration file pointing to malicious libraries
- Medium: To force symlink and timing issues for redirecting access to libraries
- High: To reverse engineering the libraries and inject malicious code into the libraries

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- Authorization: Execute Unauthorized Commands — Run Arbitrary Code
- Access Control, Authorization: Bypass Protection Mechanism

## Mitigations to bypass

- Implementation: Restrict the permission to modify the entries in the configuration file.
- Implementation: Check the integrity of the dynamically linked libraries before use them.
- Implementation: Use obfuscation and other techniques to prevent reverse engineering the libraries.

## Example instances (payload / topology hints)

- In this example, the attacker using ELF infection that redirects the Procedure Linkage Table (PLT) of an executable allowing redirection to be resident outside of the infected executable. The algorithm at the entry point code is as follows... • mark the text segment writeable • save the PLT(GOT) entry • replace the PLT(GOT) entry with the address of the new lib call The algorithm in the new libra…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-154](CAPEC-154.md)
- CanPrecede → [CAPEC-185](CAPEC-185.md)

## Related CWEs (run the cwe skill)

- [CWE-706](../cwe/references/CWE-706.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-159 and CWE IDs
