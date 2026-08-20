# CAPEC-470: Expanding Control over the Operating System from the Database

- Catalog: [CAPEC-470](https://capec.mitre.org/data/definitions/470.html)
- Abstraction: Detailed · Status: Draft
- Likelihood of attack: not stated · Typical severity: Very High
- CAPEC list: 3.9

## Attack pattern

An attacker is able to leverage access gained to the database to read / write data to the file system, compromise the operating system, create a tunnel for accessing the host machine, and use this access to potentially attack other machines on the same network as the database machine. Traditionally SQL injections attacks are viewed as a way to gain unauthorized read access to the data stored in the database, modify the data in the database, delete the data, etc. However, almost every data base management system (DBMS) system includes facilities that if compromised allow an attacker complete access to the file system, operating system, and full access to the host running the database. The attacker can then use this privileged access to launch subsequent attacks. These facilities include dropping into a command shell, creating user defined functions that can call system level libraries present on the host machine, stored procedures, etc.

## Exhaustive test law

This is a detailed pattern. Execute every listed technique in the execution flow, then mutate encodings/roles/verbs. Also run the parent Standard/Meta patterns.

A scanner hit or a single blocked request is inventory, not a CAPEC-470 test. Complete means every in-scope instance finished the execution flow (or was ruled out with saved evidence) **and** every related CWE procedure was run or dated N/A.

## Tooling (PWN)

PWN::SAST SQL modules, PWN::Plugins::BurpSuite, PWN::Plugins::Fuzz; PWN::Bounty::LifecycleAuthzReplay, PWN::Plugins::BurpSuite

## Procedure

1. **Applicability gate.** Check prerequisites and skills below. If the target cannot satisfy them, record `CAPEC-470 N/A: <reason>` and stop.
2. **Instance inventory.** List every actor/path/API/host where this pattern can run (anonymous, low-priv, high-priv, adjacent network, local). One URL is not an inventory.
3. **Oracle.** From consequences, define pass/fail (auth bypass, data out, crash, persistence, etc.).
4. **Execute the flow.** Run every Explore → Experiment → Exploit step and every listed technique. Persist request/response, pcap, or debugger output under `/tmp` or the engagement dir and **re-read** it.
5. **Mutate.** Encoding, method, role, content-type, timing, second-order, chained related CAPECs. Do not stop at the first WAF 403.
6. **Mitigation negation.** For each mitigation, retry the flow with the control on and bypassed. Unchanged oracle = control failed.
7. **CWE close-out.** Open each related `cwe` skill file (`../cwe/references/CWE-<id>.md`) and run that exhaustive CWE procedure. CAPEC without CWE is a technique note, not a weakness finding.
8. **Report.** Cite `CAPEC-470`, related CWE IDs, instance, oracle, evidence path.

## Execution flow (minimum techniques)

- Step 1 (Explore): The adversary identifies a database management system running on a machine they would like to gain control over, or on a network they want to move laterally through.
- Step 2 (Experiment): The adversary goes about the typical steps of an SQL injection and determines if an injection is possible.
- Step 3 (Experiment): Once the Adversary determines that an SQL injection is possible, they must ensure that the requirements for the attack are met. These are a high privileged session user and batched query support. This is done in similar ways to discovering if an SQL injection is possible.
- Step 4 (Experiment): If the requirements are met, based on the database management system that is running, the adversary will find or create user defined functions (UDFs) that can be loaded as DLLs. An example of a DLL can be found at https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql
- Step 5 (Experiment): In order to load the DLL, the adversary must first find the path to the plugin directory. The command to achieve this is different based on the type of DBMS, but for MySQL, this can be achieved by running the command "select @@plugin_dir"
- Step 6 (Exploit): The DLL is then moved into the previously found plugin directory so that the contained functions can be loaded. This can be done in a number of ways; loading from a network share, writing the entire hex encoded string to a file in the plugin directory, or loading the DLL into a table and then into a file. An example using MySQL to load the hex string is as follows. select 0x4d5a…
- Step 6 (Exploit): Once the DLL is in the plugin directory, a command is then run to load the UDFs. An example of this in MySQL is "create function sys_eval returns string soname 'udf.dll';" The function sys_eval is specific to the example DLL listed above.
- Step 6 (Exploit): Once the adversary has loaded the desired function(s), they will use these to execute arbitrary commands on the compromised system. This is done through a simple select command to the loaded UDF. For example: "select sys_eval('dir');". Because the prerequisite to this attack is that the database session user is a super user, this means that the adversary will be able to execute…

## Prerequisites

- A vulnerable DBMS is usedA SQL injection exists that gives an attacker access to the database or an attacker has access to the DBMS via other means

## Skills required

- High: Low level knowledge of the various facilities available in different DBMS systems for interacting with the file system and operating system

## Resources required

- (none listed in CAPEC catalog)

## Oracles (consequences)

- (none listed in CAPEC catalog)

## Mitigations to bypass

- Design: Follow the defensive programming practices needed to protect an application accessing the database from SQL injection
- Configuration: Ensure that the DBMS is patched with the latest security patches
- Design: Ensure that the DBMS login used by the application has the lowest possible level of privileges in the DBMS
- Design: Ensure that DBMS runs with the lowest possible level of privileges on the host machine and that it runs as a separate user
- Usage: Do not use the DBMS machine for anything else other than the database
- Usage: Do not place any trust in the database host on the internal network. Authenticate and validate all network activity originating from the database host.
- Usage: Use an intrusion detection system to monitor network connections and logs on the database host.
- Implementation: Remove / disable all unneeded / unused functions of the DBMS system that may allow an attacker to elevate privileges if compromised

## Example instances (payload / topology hints)

- (none listed in CAPEC catalog)

## Related CAPECs (test these too)

- ChildOf → [CAPEC-66](CAPEC-66.md)

## Related CWEs (run the cwe skill)

- [CWE-250](../cwe/references/CWE-250.md) — run that CWE procedure after this CAPEC flow
- [CWE-89](../cwe/references/CWE-89.md) — run that CWE procedure after this CAPEC flow

## Verification

- [ ] Applicability recorded (in-scope or dated N/A)
- [ ] Instance inventory is more than one guess
- [ ] Every execution-flow step was attempted or marked N/A
- [ ] Evidence artifact path saved and re-read
- [ ] Related CAPECs handled or deferred
- [ ] Related CWE procedures run via `cwe` skill
- [ ] Finding (if any) cites CAPEC-470 and CWE IDs
