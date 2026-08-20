# CAPEC-483: Deprecated Entries

- Type: View
- Status/Type field: Draft
- Catalog: [CAPEC-483](https://capec.mitre.org/data/definitions/483.html)
- CAPEC list: 3.9

## What this ID is

CAPEC nodes in this view (slice) have been deprecated.

## Exhaustive test law

Do **not** file "CAPEC-483" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- (none listed in CAPEC catalog)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-483 as the only ID when a member ID applies
