# CAPEC-36: Using Unpublished Interfaces or Functionality

- Catalog: [CAPEC-36](https://capec.mitre.org/data/definitions/36.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: Medium · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary searches for and invokes interfaces or functionality that the target system designers did not intend to be publicly available. If interfaces fail to authenticate requests, the attacker may be able to invoke functionality they are not authorized for.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-36 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-36 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-36`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify services] Discover a service of interest by exploring service registry listings or by connecting on a known port or some similar means. | techniques: Search via internet for known, published services.; Use automated tools to scan known ports to identify internet-enabled services.; Dump the code from the chip and then perform reverse engineering to analyze the code.
- Step 2 (Explore): [Authenticate to service] Authenticate to the service, if required, in order to explore it. | techniques: Use published credentials to access system.; Find unpublished credentials to access service.; Use other attack pattern or weakness to bypass authentication.
- Step 3 (Explore): [Identify all interfaces] Determine the exposed interfaces by querying the registry as well as probably sniffing to expose interfaces that are not explicitly listed. | techniques: For any published services, determine exposed interfaces via the documentation provided.; For any services found, use error messages from poorly formed service calls to determine valid interfaces. In s…
- Step 4 (Experiment): [Attempt to discover unpublished functions] Using manual or automated means, discover unpublished or undocumented functions exposed by the service. | techniques: Manually attempt calls to the service using an educated guess approach, including the use of terms like' 'test', 'debug', 'delete', etc.; Use automated tools to scan the service to attempt to reverse engineer exposed…
- Step 5 (Exploit): [Exploit unpublished functions] Using information determined via experimentation, exploit the unpublished features of the service. | techniques: Execute features that are not intended to be used by general system users.; Craft malicious calls to features not intended to be used by general system users that take advantage of security flaws found in the functions.

## Prerequisites

- The architecture under attack must publish or otherwise make available services that clients can attach to, either in an unauthenticated fashion, or having obtained an authentication token elsewhere. The service need not be 'discoverable', but in the event it isn't it must have some way of being discovered by an attacker. This might include listening on a well-known port. Ultimately, the likeliho…

## Skills required

- Low: A number of web service digging tools are available for free that help discover exposed web services and their interfaces. In the event that a web service is not listed, the attacker does not need to know much more in addition to the format of web service messages that they can sniff/monitor for.

## Resources required

- None: No specialized resources are required to execute this type of attack. Web service digging tools may be helpful.

## Oracles (consequences)

- Confidentiality: Read Data
- Confidentiality, Access Control, Authorization: Gain Privileges

## Mitigations to bypass

- Authenticating both services and their discovery, and protecting that authentication mechanism simply fixes the bulk of this problem. Protecting the authentication involves the standard means, including: 1) protecting the channel over which authentication occurs, 2) preventing the theft, forgery, or prediction of authentication credentials or the resultant tokens, or 3) subversion of password res…

## Example instances (payload / topology hints)

- To an extent, Google services (such as Google Maps) are all well-known examples. Calling these services, or extending them for one's own (perhaps very different) purposes is as easy as knowing they exist. Their unencumbered public use, however, is a purposeful aspect of Google's business model. Most organizations, however, do not have the same business model. Organizations publishing services usu…

## Related CAPECs (test these too)

- ChildOf → [CAPEC-113](CAPEC-113.md)

## Related CWEs (run the cwe skill)

- [CWE-306](../cwe/references/CWE-306.md) — run that CWE procedure after this CAPEC flow
- [CWE-693](../cwe/references/CWE-693.md) — run that CWE procedure after this CAPEC flow
- [CWE-695](../cwe/references/CWE-695.md) — run that CWE procedure after this CAPEC flow
- [CWE-1242](../cwe/references/CWE-1242.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-36 and CWE IDs
