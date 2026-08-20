# CAPEC-255: Manipulate Data Structures

- Type: Category
- Status/Type field: Stable
- Catalog: [CAPEC-255](https://capec.mitre.org/data/definitions/255.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns in this category manipulate and exploit characteristics of system data structures in order to violate the intended usage and protections of these structures. This is done in such a way that yields either improper access to the associated system data or violations of the security properties of the system itself due to vulnerabilities in how the system processes and manages the data structures. Often, vulnerabilities and therefore exploitability of these data structures exist due to ambiguity and assumption in their design and prescribed handling.

## Exhaustive test law

Do **not** file "CAPEC-255" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-123](CAPEC-123.md)
- [CAPEC-124](CAPEC-124.md)
- [CAPEC-129](CAPEC-129.md)
- [CAPEC-153](CAPEC-153.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-255 as the only ID when a member ID applies
