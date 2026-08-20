# CAPEC-223: Employ Probabilistic Techniques

- Type: Category
- Status/Type field: Stable
- Catalog: [CAPEC-223](https://capec.mitre.org/data/definitions/223.html)
- CAPEC list: 3.9

## What this ID is

An attacker utilizes probabilistic techniques to explore and overcome security properties of the target that are based on an assumption of strength due to the extremely low mathematical probability that an attacker would be able to identify and exploit the very rare specific conditions under which those security properties do not hold.

## Exhaustive test law

Do **not** file "CAPEC-223" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-112](CAPEC-112.md)
- [CAPEC-28](CAPEC-28.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-223 as the only ID when a member ID applies
