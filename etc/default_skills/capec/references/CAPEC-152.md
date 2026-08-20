# CAPEC-152: Inject Unexpected Items

- Type: Category
- Status/Type field: Stable
- Catalog: [CAPEC-152](https://capec.mitre.org/data/definitions/152.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns within this category focus on the ability to control or disrupt the behavior of a target either through crafted data submitted via an interface for data input, or the installation and execution of malicious code on the target system. The former happens when an adversary adds material to their input that is interpreted by the application causing the targeted application to perform steps unintended by the application manager or causing the application to enter an unstable state. Attacks of this type differ from Data Structure Attacks in that the latter attacks subvert the underlying structures that hold user-provided data, either pre-empting interpretation of the input (in the case of Buffer Overflows) or resulting in values that the targeted application is unable to handle correctly (in the case of Integer Overflows). In Injection attacks, the input is interpreted by the application, but the attacker has included instructions to the interpreting functions that the target application then follows.

## Exhaustive test law

Do **not** file "CAPEC-152" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-137](CAPEC-137.md)
- [CAPEC-175](CAPEC-175.md)
- [CAPEC-240](CAPEC-240.md)
- [CAPEC-242](CAPEC-242.md)
- [CAPEC-248](CAPEC-248.md)
- [CAPEC-549](CAPEC-549.md)
- [CAPEC-624](CAPEC-624.md)
- [CAPEC-594](CAPEC-594.md)
- [CAPEC-586](CAPEC-586.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-152 as the only ID when a member ID applies
