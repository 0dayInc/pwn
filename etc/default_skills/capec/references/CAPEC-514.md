# CAPEC-514: Physical Security

- Type: Category
- Status/Type field: Draft
- Catalog: [CAPEC-514](https://capec.mitre.org/data/definitions/514.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns within this category focus on physical security. The techniques defined by each pattern are used to exploit weaknesses in the physical security of a system in an attempt to achieve a desired negative technical impact.

## Exhaustive test law

Do **not** file "CAPEC-514" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-116](CAPEC-116.md)
- [CAPEC-117](CAPEC-117.md)
- [CAPEC-188](CAPEC-188.md)
- [CAPEC-390](CAPEC-390.md)
- [CAPEC-440](CAPEC-440.md)
- [CAPEC-507](CAPEC-507.md)
- [CAPEC-607](CAPEC-607.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-514 as the only ID when a member ID applies
