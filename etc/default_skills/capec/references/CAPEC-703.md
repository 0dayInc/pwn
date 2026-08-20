# CAPEC-703: Industrial Control System (ICS) Patterns

- Type: View
- Status/Type field: Draft
- Catalog: [CAPEC-703](https://capec.mitre.org/data/definitions/703.html)
- CAPEC list: 3.9

## What this ID is

This view contains a listing of CAPECs that apply to industrial control systems (ICS). Some children of these attack patterns might also be applicable.

## Exhaustive test law

Do **not** file "CAPEC-703" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-1](CAPEC-1.md)
- [CAPEC-57](CAPEC-57.md)
- [CAPEC-65](CAPEC-65.md)
- [CAPEC-70](CAPEC-70.md)
- [CAPEC-94](CAPEC-94.md)
- [CAPEC-98](CAPEC-98.md)
- [CAPEC-125](CAPEC-125.md)
- [CAPEC-130](CAPEC-130.md)
- [CAPEC-131](CAPEC-131.md)
- [CAPEC-141](CAPEC-141.md)
- [CAPEC-148](CAPEC-148.md)
- [CAPEC-158](CAPEC-158.md)
- [CAPEC-163](CAPEC-163.md)
- [CAPEC-165](CAPEC-165.md)
- [CAPEC-169](CAPEC-169.md)
- [CAPEC-177](CAPEC-177.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-703 as the only ID when a member ID applies
