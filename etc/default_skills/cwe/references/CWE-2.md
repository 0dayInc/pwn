# CWE-2: 7PK - Environment

- Type: Category
- Status/Type field: Draft
- Catalog: [CWE-2](https://cwe.mitre.org/data/definitions/2.html)
- CWE list: 4.20

## What this ID is

This category represents one of the phyla in the Seven Pernicious Kingdoms vulnerability classification. It includes weaknesses that are typically introduced during unexpected environmental conditions. According to the authors of the Seven Pernicious Kingdoms, "This section includes everything that is outside of the source code but is still critical to the security of the product that is being created. Because the issues covered by this kingdom are not directly related to source code, we separated it from the rest of the kingdoms."

## Exhaustive test law

Do **not** file "CWE-2" as a vulnerability. Walk every member. For each member ID, open `references/CWE-<id>.md` and run that procedure. Exhaustion = every member tested or ruled out with evidence.

If a member is Deprecated, still map it to its replacement and test the replacement.

## Members to test

- [CWE-11](CWE-11.md)
- [CWE-12](CWE-12.md)
- [CWE-13](CWE-13.md)
- [CWE-14](CWE-14.md)
- [CWE-5](CWE-5.md)
- [CWE-6](CWE-6.md)
- [CWE-7](CWE-7.md)
- [CWE-8](CWE-8.md)
- [CWE-9](CWE-9.md)

## Procedure

1. Copy the member list into the engagement notes.
2. For each member, load `references/CWE-<id>.md`.
3. Run that file's procedure against the target.
4. Tick the member off only when its Verification checklist is done.
5. Summarize coverage: tested / N/A / blocked, with evidence paths.

## Verification

- [ ] Member list captured
- [ ] Every member has a result (tested, N/A, or blocked)
- [ ] No finding uses CWE-2 as the only ID when a member ID applies
