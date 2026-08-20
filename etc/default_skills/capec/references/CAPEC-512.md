# CAPEC-512: Communications

- Type: Category
- Status/Type field: Draft
- Catalog: [CAPEC-512](https://capec.mitre.org/data/definitions/512.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns within this category focus on the exploitation of communications and related protocols. The techniques defined by each pattern are used by an adversary to block, manipulate, and steal communications in an attempt to achieve a desired negative technical impact.

## Exhaustive test law

Do **not** file "CAPEC-512" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-22](CAPEC-22.md)
- [CAPEC-94](CAPEC-94.md)
- [CAPEC-117](CAPEC-117.md)
- [CAPEC-125](CAPEC-125.md)
- [CAPEC-130](CAPEC-130.md)
- [CAPEC-148](CAPEC-148.md)
- [CAPEC-151](CAPEC-151.md)
- [CAPEC-154](CAPEC-154.md)
- [CAPEC-161](CAPEC-161.md)
- [CAPEC-169](CAPEC-169.md)
- [CAPEC-192](CAPEC-192.md)
- [CAPEC-216](CAPEC-216.md)
- [CAPEC-240](CAPEC-240.md)
- [CAPEC-272](CAPEC-272.md)
- [CAPEC-594](CAPEC-594.md)
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
- [ ] No finding uses CAPEC-512 as the only ID when a member ID applies
