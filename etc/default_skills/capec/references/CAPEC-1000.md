# CAPEC-1000: Mechanisms of Attack

- Type: View
- Status/Type field: Stable
- Catalog: [CAPEC-1000](https://capec.mitre.org/data/definitions/1000.html)
- CAPEC list: 3.9

## What this ID is

This view organizes attack patterns hierarchically based on mechanisms that are frequently employed when exploiting a vulnerability. The categories that are members of this view represent the different techniques used to attack a system. They do not, however, represent the consequences or goals of the attacks. There exists the potential for some attack patterns to align with more than one category depending on one’s perspective. To counter this, emphasis was placed such that attack patterns as presented within each category use a technique not sometimes, but without exception.

## Exhaustive test law

Do **not** file "CAPEC-1000" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-156](CAPEC-156.md)
- [CAPEC-210](CAPEC-210.md)
- [CAPEC-255](CAPEC-255.md)
- [CAPEC-262](CAPEC-262.md)
- [CAPEC-152](CAPEC-152.md)
- [CAPEC-223](CAPEC-223.md)
- [CAPEC-172](CAPEC-172.md)
- [CAPEC-118](CAPEC-118.md)
- [CAPEC-225](CAPEC-225.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-1000 as the only ID when a member ID applies
