# CAPEC-118: Collect and Analyze Information

- Type: Category
- Status/Type field: Stable
- Catalog: [CAPEC-118](https://capec.mitre.org/data/definitions/118.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns within this category focus on the gathering, collection, and theft of information by an adversary. The adversary may collect this information through a variety of methods including active querying as well as passive observation. By exploiting weaknesses in the design or configuration of the target and its communications, an adversary is able to get the target to reveal more information than intended. Information retrieved may aid the adversary in making inferences about potential weaknesses, vulnerabilities, or techniques that assist the adversary's objectives. This information may include details regarding the configuration or capabilities of the target, clues as to the timing or nature of activities, or otherwise sensitive information. Often this sort of attack is undertaken in preparation for some other type of attack, although the collection of information by itself may in some cases be the end goal of the adversary.

## Exhaustive test law

Do **not** file "CAPEC-118" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-116](CAPEC-116.md)
- [CAPEC-117](CAPEC-117.md)
- [CAPEC-169](CAPEC-169.md)
- [CAPEC-224](CAPEC-224.md)
- [CAPEC-188](CAPEC-188.md)
- [CAPEC-192](CAPEC-192.md)
- [CAPEC-410](CAPEC-410.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-118 as the only ID when a member ID applies
