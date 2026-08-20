# CAPEC-156: Engage in Deceptive Interactions

- Type: Category
- Status/Type field: Stable
- Catalog: [CAPEC-156](https://capec.mitre.org/data/definitions/156.html)
- CAPEC list: 3.9

## What this ID is

Attack patterns within this category focus on malicious interactions with a target in an attempt to deceive the target and convince the target that it is interacting with some other principal and as such take actions based on the level of trust that exists between the target and the other principal. These types of attacks assume that some piece of content or functionality is associated with an identity and that the content / functionality is trusted by the target because of this association. Often identified by the term "spoofing", these types of attacks rely on the falsification of the content and/or identity in such a way that the target will incorrectly trust the legitimacy of the content. For example, an attacker may modify a financial transaction between two parties so that the participants remain unchanged but the amount of the transaction is increased. If the recipient cannot detect the change, they may incorrectly assume the modified message originated with the original sender. Attacks of these type may involve an adversary crafting the content from scratch or capturing and modifying legitimate content.

## Exhaustive test law

Do **not** file "CAPEC-156" as the only finding ID. Walk every member. For each member, open `references/CAPEC-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

## Members to test

- [CAPEC-148](CAPEC-148.md)
- [CAPEC-151](CAPEC-151.md)
- [CAPEC-154](CAPEC-154.md)
- [CAPEC-173](CAPEC-173.md)
- [CAPEC-416](CAPEC-416.md)
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
- [ ] No finding uses CAPEC-156 as the only ID when a member ID applies
