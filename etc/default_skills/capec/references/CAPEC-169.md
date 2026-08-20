# CAPEC-169: Footprinting

- Catalog: [CAPEC-169](https://capec.mitre.org/data/definitions/169.html)
- Abstraction: Meta · Status: Stable
- Likelihood of attack: High · Typical severity: Very Low
- CAPEC list: 3.9

## Attack pattern

An adversary engages in probing and exploration activities to identify constituents and properties of the target.

## Exhaustive test law

This is a meta pattern. Do not stop at the name. Open every ChildOf / Has_Member descendant `references/CAPEC-<id>.md` and run those procedures. Exhaustion = every applicable child tested or N/A with evidence.

A scanner hit or a single blocked request is inventory, not a CAPEC-169 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

skills_recall capec → read references/CAPEC-<id>.md; then skills_recall cwe for each related CWE; pwn_eval / BurpSuite / TransparentBrowser / SAST as the surface requires

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-169 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-169`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Request Footprinting] The attacker examines the website information and source code of the website and uses automated tools to get as much information as possible about the system and organization. | techniques: Open Source Footprinting: Examine the website about the organization and skim through the webpage's HTML source to look for comments.; Network Enumeration: Perform vari…

## Prerequisites

- An application must publicize identifiable information about the system or application through voluntary or involuntary means. Certain identification details of information systems are visible on communication networks (e.g., if an adversary uses a sniffer to inspect the traffic) due to their inherent structure and protocol standards. Any system or network that can be detected can be footprinted.…

## Skills required

- Low: The adversary knows how to send HTTP request, run the scan tool.

## Resources required

- The adversary requires a variety of tools to collect information about the target. These include port/network scanners and tools to analyze responses from applications to determine version and configuration information. Footprinting a system adequately may also take a few days if the attacker wishes the footprinting attempt to go undetected.

## Oracles (consequences)

- Confidentiality: Read Data

## Mitigations to bypass

- Keep patches up to date by installing weekly or daily if possible.
- Shut down unnecessary services/ports.
- Change default passwords by choosing strong passwords.
- Curtail unexpected input.
- Encrypt and password-protect sensitive data.
- Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

## Example instances (payload / topology hints)

- In this example let us look at the website http://www.example.com to get much information we can about Alice. From the website, we find that Alice also runs foobar.org. We type in www example.com into the prompt of the Name Lookup window in a tool, and our result is this IP address: 192.173.28.130 We type the domain into the Name Lookup prompt and we are given the same IP. We can safely say that…

## Related CAPECs (test these too)

- (none listed in CAPEC catalog)

## Related CWEs (run the cwe skill)

- [CWE-200](../cwe/references/CWE-200.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-169 and CWE IDs
