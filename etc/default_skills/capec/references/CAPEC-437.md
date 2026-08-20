# CAPEC-437: Supply Chain

- Type: Category
- Status/Type field: Draft
- Catalog: [CAPEC-437](https://capec.mitre.org/data/definitions/437.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns within this category focus on the disruption of the supply chain lifecycle by manipulating computer system hardware, software, or services for the purpose of espionage, theft of critical data or technology, or the disruption of mission-critical operations or infrastructure. Supply chain operations are usually multi-national with parts, components, assembly, and delivery occurring across multiple countries offering an attacker multiple points for disruption.

## Exhaustive test law

Do **not** file "CAPEC-437" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-116](CAPEC-116.md)
- [CAPEC-154](CAPEC-154.md)
- [CAPEC-176](CAPEC-176.md)
- [CAPEC-184](CAPEC-184.md)
- [CAPEC-438](CAPEC-438.md)
- [CAPEC-439](CAPEC-439.md)
- [CAPEC-440](CAPEC-440.md)
- [CAPEC-690](CAPEC-690.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-437 as the only ID when a member ID applies
