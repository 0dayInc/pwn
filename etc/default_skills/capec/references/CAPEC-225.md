# CAPEC-225: Subvert Access Control

- Type: Category
- Status/Type field: Stable
- Catalog: [CAPEC-225](https://capec.mitre.org/data/definitions/225.html)
- CAPEC list: 3.9

## What this ID is

An attacker actively targets exploitation of weaknesses, limitations and assumptions in the mechanisms a target utilizes to manage identity and authentication as well as manage access to its resources or authorize functionality. Such exploitation can lead to the complete subversion of any trust the target system may have in the identity of any entity with which it interacts, or the complete subversion of any control the target has over its data or functionality. Weaknesses targeted by subversion of authorization controls are often due to three primary factors: 1) a fundamental dependence on authentication mechanisms being effective; 2) a lack of effective control over the separation of privilege between various entities; and 3) assumptions and over confidence in the strength or rigor of the implemented authorization mechanisms.

## Exhaustive test law

Do **not** file "CAPEC-225" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-21](CAPEC-21.md)
- [CAPEC-114](CAPEC-114.md)
- [CAPEC-115](CAPEC-115.md)
- [CAPEC-22](CAPEC-22.md)
- [CAPEC-94](CAPEC-94.md)
- [CAPEC-122](CAPEC-122.md)
- [CAPEC-233](CAPEC-233.md)
- [CAPEC-390](CAPEC-390.md)
- [CAPEC-507](CAPEC-507.md)
- [CAPEC-560](CAPEC-560.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-225 as the only ID when a member ID applies
