# CAPEC-403: Social Engineering

- Type: Category
- Status/Type field: Draft
- Catalog: [CAPEC-403](https://capec.mitre.org/data/definitions/403.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns within this category focus on the manipulation and exploitation of people. The techniques defined by each pattern are used to convince a target into performing actions or divulging confidential information that benefit the adversary, often resulting in access to computer systems or facilities. While similar to a confidence trick or simple fraud, the term typically applies to trickery or deception for the purpose of information gathering, fraud, or computer system access. In most cases, the adversary never comes face-to-face with the victim.

## Exhaustive test law

Do **not** file "CAPEC-403" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-137](CAPEC-137.md)
- [CAPEC-151](CAPEC-151.md)
- [CAPEC-154](CAPEC-154.md)
- [CAPEC-173](CAPEC-173.md)
- [CAPEC-184](CAPEC-184.md)
- [CAPEC-410](CAPEC-410.md)
- [CAPEC-416](CAPEC-416.md)
- [CAPEC-607](CAPEC-607.md)
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
- [ ] No finding uses CAPEC-403 as the only ID when a member ID applies
