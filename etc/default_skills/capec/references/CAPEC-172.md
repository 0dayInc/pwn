# CAPEC-172: Manipulate Timing and State

- Type: Category
- Status/Type field: Stable
- Catalog: [CAPEC-172](https://capec.mitre.org/data/definitions/172.html)
- CAPEC list: 3.9

## What this ID is

An attacker exploits weaknesses in timing or state maintaining functions to perform actions that would otherwise be prevented by the execution flow of the target code and processes. An example of a state attack might include manipulation of an application's information to change the apparent credentials or similar information, possibly allowing the application to access material it would not normally be allowed to access. A common example of a timing attack is a test-action race condition where some state information is tested and, if it passes, an action is performed. If the attacker can change the state between the time that the application performs the test and the time the action is performed, then they might be able to manipulate the outcome of the action to malicious ends.

## Exhaustive test law

Do **not** file "CAPEC-172" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-25](CAPEC-25.md)
- [CAPEC-26](CAPEC-26.md)
- [CAPEC-74](CAPEC-74.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-172 as the only ID when a member ID applies
