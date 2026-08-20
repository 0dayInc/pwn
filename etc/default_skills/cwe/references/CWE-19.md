# CWE-19: Data Processing Errors

- Type: Category
- Status/Type field: Draft
- Catalog: [CWE-19](https://cwe.mitre.org/data/definitions/19.html)
- CWE list: 4.20

## What this ID is

Weaknesses in this category are typically found in functionality that processes data. Data processing is the manipulation of input to retrieve or save information.

## Exhaustive test law

Do **not** file "CWE-19" as a vulnerability. Walk every member. For each member ID, open `references/CWE-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

If a member is Deprecated, still map it to its replacement and test the replacement.

## Members to test

- [CWE-130](CWE-130.md)
- [CWE-166](CWE-166.md)
- [CWE-167](CWE-167.md)
- [CWE-168](CWE-168.md)
- [CWE-178](CWE-178.md)
- [CWE-182](CWE-182.md)
- [CWE-186](CWE-186.md)
- [CWE-229](CWE-229.md)
- [CWE-233](CWE-233.md)
- [CWE-237](CWE-237.md)
- [CWE-241](CWE-241.md)
- [CWE-409](CWE-409.md)

## Procedure

1. Copy the member list into the engagement notes.
2. For each member, load `references/CWE-<id>.md`.
3. Run that file's procedure against the target.
4. Tick the member off only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result (tested, N/A, or blocked)
- [ ] No finding uses CWE-19 as the only ID when a member ID applies
