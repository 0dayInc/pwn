# CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs

- Catalog: [CAPEC-1](https://capec.mitre.org/data/definitions/1.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

In applications, particularly web applications, access to functionality is mitigated by an authorization framework. This framework maps Access Control Lists (ACLs) to elements of the application's functionality; particularly URL's for web apps. In the case that the administrator failed to specify an ACL for a particular element, an attacker may be able to access it with impunity. An attacker with the ability to access functionality not properly constrained by ACLs can obtain sensitive information and possibly compromise the entire application. Such an attacker can access resources that must be available only to users at a higher privilege level, can access management sections of the application, or can run queries for data that they otherwise not supposed to.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-1 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-1 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-1`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Survey] The attacker surveys the target application, possibly as a valid and authenticated user | techniques: Spidering web sites for all available links; Brute force guessing of resource names; Brute force guessing of user names / credentials; Brute force guessing of function names / actions
- Step 2 (Explore): [Identify Functionality] At each step, the attacker notes the resource or functionality access mechanism invoked upon performing specific actions | techniques: Use the web inventory of all forms and inputs and apply attack data to those inputs.; Use a packet sniffer to capture and record network traffic; Execute the software in a debugger and record API calls into the operating…
- Step 3 (Experiment): [Iterate over access capabilities] Possibly as a valid user, the attacker then tries to access each of the noted access mechanisms directly in order to perform functions not constrained by the ACLs. | techniques: Fuzzing of API parameters (URL parameters, OS API parameters, protocol parameters)

## Prerequisites

- The application must be navigable in a manner that associates elements (subsections) of the application with ACLs.
- The various resources, or individual URLs, must be somehow discoverable by the attacker
- The administrator must have forgotten to associate an ACL or has associated an inappropriately permissive ACL with a particular navigable resource.

## Skills required

- Low: In order to discover unrestricted resources, the attacker does not need special tools or skills. They only have to observe the resources or access mechanisms invoked as each action is performed and then try and access those access mechanisms directly.

## Resources required

- None: No specialized resources are required to execute this type of attack.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- In a J2EE setting, administrators can associate a role that is impossible for the authenticator to grant users, such as "NoAccess", with all Servlets to which access is guarded by a limited number of servlets visible to, and accessible by, the user. Having done so, any direct access to those protected Servlets will be prohibited by the web container. In a more general setting, the administrator m…

## Example instances (payload / topology hints)

- Implementing the Model-View-Controller (MVC) within Java EE's Servlet paradigm using a "Single front controller" pattern that demands that brokered HTTP requests be authenticated before hand-offs to other Action Servlets. If no security-constraint is placed on those Action Servlets, such that positively no one can access them, the front controller can be subverted.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-122](CAPEC-122.md)
- CanPrecede → [CAPEC-17](CAPEC-17.md)

## Related CWEs (run the cwe skill)

- [CWE-276](../cwe/references/CWE-276.md) — run that CWE procedure after this CAPEC flow
- [CWE-285](../cwe/references/CWE-285.md) — run that CWE procedure after this CAPEC flow
- [CWE-434](../cwe/references/CWE-434.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow
- [CWE-732](../cwe/references/CWE-732.md) — run that CWE procedure after this CAPEC flow
- [CWE-1191](../cwe/references/CWE-1191.md) — run that CWE procedure after this CAPEC flow
- [CWE-1193](../cwe/references/CWE-1193.md) — run that CWE procedure after this CAPEC flow
- [CWE-1220](../cwe/references/CWE-1220.md) — run that CWE procedure after this CAPEC flow
- [CWE-1297](../cwe/references/CWE-1297.md) — run that CWE procedure after this CAPEC flow
- [CWE-1311](../cwe/references/CWE-1311.md) — run that CWE procedure after this CAPEC flow
- [CWE-1314](../cwe/references/CWE-1314.md) — run that CWE procedure after this CAPEC flow
- [CWE-1315](../cwe/references/CWE-1315.md) — run that CWE procedure after this CAPEC flow
- [CWE-1318](../cwe/references/CWE-1318.md) — run that CWE procedure after this CAPEC flow
- [CWE-1320](../cwe/references/CWE-1320.md) — run that CWE procedure after this CAPEC flow
- [CWE-1321](../cwe/references/CWE-1321.md) — run that CWE procedure after this CAPEC flow
- [CWE-1327](../cwe/references/CWE-1327.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-1 and CWE IDs
