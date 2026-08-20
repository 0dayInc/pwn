# CAPEC-210: Abuse Existing Functionality

- Type: Category
- Status/Type field: Stable
- Catalog: [CAPEC-210](https://capec.mitre.org/data/definitions/210.html)
- CAPEC list: 3.9

## What this ID is

An adversary uses or manipulates one or more functions of an application in order to achieve a malicious objective not originally intended by the application, or to deplete a resource to the point that the target's functionality is affected. This is a broad class of attacks wherein the adversary is able to alter the intended result or purpose of the functionality and thereby affect application behavior or information integrity. Outcomes can range from information exposure, vandalism, degrading or denial of service, as well as execution of arbitrary code on the target machine.

## Exhaustive test law

Do **not** file "CAPEC-210" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-113](CAPEC-113.md)
- [CAPEC-125](CAPEC-125.md)
- [CAPEC-130](CAPEC-130.md)
- [CAPEC-131](CAPEC-131.md)
- [CAPEC-212](CAPEC-212.md)
- [CAPEC-216](CAPEC-216.md)
- [CAPEC-227](CAPEC-227.md)
- [CAPEC-272](CAPEC-272.md)
- [CAPEC-554](CAPEC-554.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-210 as the only ID when a member ID applies
