---
name: rop-jop-chain-construction
description: Use when building ROP/JOP. Debugger and REDB gadgets.
---

# ROP / JOP chain construction

1. `PWN::Plugins::REDB.funcs` and `PWN::Plugins::ROP` gadget search.
2. `PWN::Plugins::Debugger.cyclic_find` for the overflow offset.
3. Write the chain with `ExploitDev.p64` and verify `regs` after `continue`.
