# CAPEC-515: Hardware

- Type: Category
- Status/Type field: Draft
- Catalog: [CAPEC-515](https://capec.mitre.org/data/definitions/515.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns within this category focus on the exploitation of the physical hardware used in computing systems. The techniques defined by each pattern reflect the replacement, destruction, modification and exploitation of hardware components that make up a system in an attempt to achieve a desired negative technical impact. Attacks against hardware component fall into several broad categories depending upon the relative sophistication of the attacker and the type of systems that are targeted. Attacks against hardware components differ from software attacks in that hardware-based attacks target the chips, circuit boards, device ports, or other components that comprise a computer system or embedded system. Sophisticated attacks may involve adding or removing jumpers to an exposed system, or applying sensors to portions of the motherboard to read data as it traverses the system bus.

## Exhaustive test law

Do **not** file "CAPEC-515" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-26](CAPEC-26.md)
- [CAPEC-74](CAPEC-74.md)
- [CAPEC-113](CAPEC-113.md)
- [CAPEC-114](CAPEC-114.md)
- [CAPEC-116](CAPEC-116.md)
- [CAPEC-122](CAPEC-122.md)
- [CAPEC-124](CAPEC-124.md)
- [CAPEC-148](CAPEC-148.md)
- [CAPEC-151](CAPEC-151.md)
- [CAPEC-154](CAPEC-154.md)
- [CAPEC-161](CAPEC-161.md)
- [CAPEC-176](CAPEC-176.md)
- [CAPEC-188](CAPEC-188.md)
- [CAPEC-192](CAPEC-192.md)
- [CAPEC-212](CAPEC-212.md)
- [CAPEC-233](CAPEC-233.md)

## Procedure

1. Copy the member list into engagement notes.
2. For each member, load `references/CAPEC-<id>.md`.
3. Run that file's procedure, including related CWE files in the `cwe` skill.
4. Tick a member only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result
- [ ] No finding uses CAPEC-515 as the only ID when a member ID applies
