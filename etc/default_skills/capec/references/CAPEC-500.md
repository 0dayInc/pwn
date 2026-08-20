# CAPEC-500: WebView Injection

- Catalog: [CAPEC-500](https://capec.mitre.org/data/definitions/500.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: not stated
- CAPEC list: 3.9

## Attack pattern

An adversary, through a previously installed malicious application, injects code into the context of a web page displayed by a WebView component. Through the injected code, an adversary is able to manipulate the DOM tree and cookies of the page, expose sensitive information, and can launch attacks against the web application from within the web page.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-500 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-500 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-500`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Determine target web application] An adversary first needs to determine what web application they wish to target. | techniques: Target web applications that require users to enter sensitive information.; Target web applications that an adversary wishes to operate on behalf of a logged in user.
- Step 2 (Experiment): [Create malicious application] An adversary creates an application, often mobile, that incorporates a WebView component to display the targeted web application. This malicious application needs to downloaded by a user, so adversaries will make this application useful in some way. | techniques: Create a 3rd party application that adds useful functionality to the targeted web a…
- Step 3 (Experiment): [Get the victim to download and run the application] An adversary needs to get the victim to willingly download and run the application. | techniques: Pay for App Store advertisements; Promote the application on social media, either through accounts made by the adversary or by paying for other accounts to advertise.
- Step 4 (Exploit): [Inject malicious code] Once the victim runs the malicious application and views the targeted web page in the WebView component, the malicious application will inject malicious JavaScript code into the web application. This is done by using WebView's loadURL() API, which can inject arbitrary JavaScript code into pages loaded by the WebView component with the same privileges. Thi…

## Prerequisites

- An adversary must be able install a purpose built malicious application onto the device and convince the user to execute it. The malicious application is designed to target a specific web application and is used to load the target web pages via the WebView component. For example, an adversary may develop an application that interacts with Facebook via WebView and adds a new feature that a user de…

## Skills required

- (none listed in CAPEC catalog)

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- The only known mitigation to this type of attack is to keep the malicious application off the system. There is nothing that can be done to the target application to protect itself from a malicious application that has been installed and executed.

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-253](CAPEC-253.md)

## Related CWEs (run the cwe skill)

- [CWE-749](../cwe/references/CWE-749.md) — run that CWE procedure after this CAPEC flow
- [CWE-940](../cwe/references/CWE-940.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-500 and CWE IDs
