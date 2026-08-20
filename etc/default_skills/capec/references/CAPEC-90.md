# CAPEC-90: Reflection Attack in Authentication Protocol

- Catalog: [CAPEC-90](https://capec.mitre.org/data/definitions/90.html)
- Abstraction: Standard · Status: Draft
- Likelihood of attack: High · Typical severity: High
- CAPEC list: 3.9

## Attack pattern

An adversary can abuse an authentication protocol susceptible to reflection attack in order to defeat it. Doing so allows the adversary illegitimate access to the target system, without possessing the requisite credentials. Reflection attacks are of great concern to authentication protocols that rely on a challenge-handshake or similar mechanism. An adversary can impersonate a legitimate user and can gain illegitimate access to the system by successfully mounting a reflection attack during authentication.

## Exhaustive test law

This is a standard pattern. Inventory every place the execution flow can apply, then run every Explore/Experiment/Exploit step against each instance. One successful probe is not exhaustion.

A scanner hit or a single blocked request is inventory, not a CAPEC-90 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::Plugins::Fuzz, PWN::Plugins::AuthenticationHelper, hydra/ncrack via shell; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-90 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-90`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): [Identify service with vulnerable handshake authentication] The adversary must first identify a vulnerable authentication protocol. The most common indication of an authentication protocol vulnerable to reflection attack is when the client initiates the handshake, rather than the server. This allows the client to get the server to encrypt targeted data using the server's pre-sha…
- Step 2 (Experiment): [Send challenge to target server] The adversary opens a connection to the target server and sends it a challenge. This challenge is arbitrary and is simply used as a placeholder for the protocol in order to get the server to respond.
- Step 3 (Experiment): [Receive server challenge] The server responds by returning the challenge sent encrypted with the server's pre-shared key, as well as its own challenge to the attacker sent in plaintext. We will call this challenge sent by the server "C". C is very important and is stored off by the adversary for the next step.
- Step 4 (Experiment): [Initiate second handshake] Since the adversary does not possess the pre-shared key, they cannot encrypt C from the previous step in order for the server to authenticate them. To get around this, the adversary initiates a second connection to the server while still keeping the first connection alive. In the second connection, the adversary sends C as the initial client challe…
- Step 5 (Experiment): [Receive encrypted challenge] The server treats the intial client challenge in connection two as an arbitrary client challenge and responds by encrypting C with the pre-shared key. The server also sends a new challenge. The adversary ignores the server challenge and stores the encrypted version of C. The second connection is either terminated or left to expire by the adversar…
- Step 6 (Exploit): The adversary now posseses the encrypted version of C that is obtained through connection two. The adversary continues the handshake in connection one by responding to the server with the encrypted version of C, verifying that they have access to the pre-shared key (when they actually do not). Because the server uses the same pre-shared key for all authentication it will decrypt…

## Prerequisites

- The attacker must have direct access to the target server in order to successfully mount a reflection attack. An intermediate entity, such as a router or proxy, that handles these exchanges on behalf of the attacker inhibits the attackers' ability to attack the authentication protocol.

## Skills required

- Medium: The attacker needs to have knowledge of observing the protocol exchange and managing the required connections in order to issue and respond to challenges

## Resources required

- All that the attacker requires is a means to observe and understand the protocol exchanges in order to reflect the challenges appropriately.

## Oracles (consequences)

- Confidentiality, Access Control, Authorization: Gain Privileges, Bypass Protection Mechanism
- Confidentiality: Read Data

## Mitigations to bypass

- The server must initiate the handshake by issuing the challenge. This ensures that the client has to respond before the exchange can move any further
- The use of HMAC to hash the response from the server can also be used to thwart reflection. The server responds by returning its own challenge as well as hashing the client's challenge, its own challenge and the pre-shared secret. Requiring the client to respond with the HMAC of the two challenges ensures that only the possessor of a valid pre-shared secret can successfully hash in the two values.
- Introducing a random nonce with each new connection ensures that the attacker cannot employ two connections to attack the authentication protocol

## Example instances (payload / topology hints)

- A single sign-on solution for a network uses a fixed pre-shared key with its clients to initiate the sign-on process in order to avoid eavesdropping on the initial exchanges. An attacker can use a reflection attack to mimic a trusted client on the network to participate in the sign-on exchange.

## Related CAPECs (test these too)

- ChildOf → [CAPEC-272](CAPEC-272.md)
- ChildOf → [CAPEC-114](CAPEC-114.md)

## Related CWEs (run the cwe skill)

- [CWE-301](../cwe/references/CWE-301.md) — run that CWE procedure after this CAPEC flow
- [CWE-303](../cwe/references/CWE-303.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-90 and CWE IDs
