# CAPEC-683: Supply Chain Risks

- Type: View
- Status/Type field: Draft
- Catalog: [CAPEC-683](https://capec.mitre.org/data/definitions/683.html)
- CAPEC list: 3.9

## What this ID is

This view covers patterns that fall within the CISA Supply Chain Lifecycle

## Exhaustive test law

Do **not** file "CAPEC-683" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-684](CAPEC-684.md)
- [CAPEC-685](CAPEC-685.md)
- [CAPEC-686](CAPEC-686.md)
- [CAPEC-687](CAPEC-687.md)
- [CAPEC-688](CAPEC-688.md)
- [CAPEC-689](CAPEC-689.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-683 as the only ID when a member ID applies
