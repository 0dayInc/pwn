# The pwn REPL

The `pwn` command launches a Pry-based interactive Ruby shell with the entire `PWN` namespace pre-loaded.

## Starting

```bash
pwn
pwn[v0.5.613]:001 >>>
```

## Key Features

- Direct access to every `PWN::` constant and plugin.
- Tab completion for classes and methods.
- Multi-line support.
- Easy prototyping of security workflows.
- `PWN.help` and inspection of any object.

## Useful REPL Commands

```
pwn[v0.5.613]:001 >>> PWN::Plugins.constants.sort
pwn[v0.5.613]:001 >>> PWN::Plugins::BurpSuite.methods(false).sort
pwn[v0.5.613]:001 >>> PWN::SAST.constants
pwn[v0.5.613]:001 >>> pwn-ai
```

See:
- [pwn-ai Agent](pwn-ai-Agent.md) — the killer feature inside the REPL
- [General Usage](General-PWN-Usage.md)

[[Diagrams]]
