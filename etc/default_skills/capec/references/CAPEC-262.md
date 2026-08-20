# CAPEC-262: Manipulate System Resources

- Type: Category
- Status/Type field: Stable
- Catalog: [CAPEC-262](https://capec.mitre.org/data/definitions/262.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns within this category focus on the adversary's ability to manipulate one or more resources in order to achieve a desired outcome. This is a broad class of attacks wherein the attacker is able to change some aspect of a resource's state or availability and thereby affect system behavior or information integrity. Examples of resources include files, applications, libraries, infrastructure, and configuration information. Outcomes can range from vandalism and reduction in service to the execution of arbitrary code on the target machine.

## Exhaustive test law

Do **not** file "CAPEC-262" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-184](CAPEC-184.md)
- [CAPEC-440](CAPEC-440.md)
- [CAPEC-161](CAPEC-161.md)
- [CAPEC-165](CAPEC-165.md)
- [CAPEC-176](CAPEC-176.md)
- [CAPEC-607](CAPEC-607.md)
- [CAPEC-438](CAPEC-438.md)
- [CAPEC-439](CAPEC-439.md)
- [CAPEC-441](CAPEC-441.md)
- [CAPEC-548](CAPEC-548.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-262 as the only ID when a member ID applies
