# CAPEC-3000: Domains of Attack

- Type: View
- Status/Type field: Draft
- Catalog: [CAPEC-3000](https://capec.mitre.org/data/definitions/3000.html)
- CAPEC list: 3.9

## What this ID is

This view organizes attack patterns hierarchically based on the attack domain.

## Exhaustive test law

Do **not** file "CAPEC-3000" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-513](CAPEC-513.md)
- [CAPEC-515](CAPEC-515.md)
- [CAPEC-512](CAPEC-512.md)
- [CAPEC-437](CAPEC-437.md)
- [CAPEC-403](CAPEC-403.md)
- [CAPEC-514](CAPEC-514.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-3000 as the only ID when a member ID applies
