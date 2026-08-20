# CAPEC-513: Software

- Type: Category
- Status/Type field: Draft
- Catalog: [CAPEC-513](https://capec.mitre.org/data/definitions/513.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns within this category focus on the exploitation of software applications. The techniques defined by each pattern are used to exploit these weaknesses in the application's design or implementation in an attempt to achieve a desired negative technical impact.

## Exhaustive test law

Do **not** file "CAPEC-513" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-21](CAPEC-21.md)
- [CAPEC-22](CAPEC-22.md)
- [CAPEC-25](CAPEC-25.md)
- [CAPEC-26](CAPEC-26.md)
- [CAPEC-28](CAPEC-28.md)
- [CAPEC-74](CAPEC-74.md)
- [CAPEC-94](CAPEC-94.md)
- [CAPEC-112](CAPEC-112.md)
- [CAPEC-113](CAPEC-113.md)
- [CAPEC-114](CAPEC-114.md)
- [CAPEC-115](CAPEC-115.md)
- [CAPEC-116](CAPEC-116.md)
- [CAPEC-117](CAPEC-117.md)
- [CAPEC-122](CAPEC-122.md)
- [CAPEC-123](CAPEC-123.md)
- [CAPEC-124](CAPEC-124.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-513 as the only ID when a member ID applies
