---
name: windows-internals-triage
description: Use when triaging Windows binaries. REDB plus Debugger.
---

# Windows internals triage

1. `PWN::Plugins::REDB.strings(match: 'ntdll')` on the PE.
2. Imports/exports from `funcs`; xrefs for interesting APIs.
3. Live verification uses `PWN::Plugins::Debugger` when a gdbstub exists.
