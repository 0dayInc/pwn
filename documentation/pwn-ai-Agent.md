# pwn-ai Autonomous Agent

The most powerful way to use PWN is via the `pwn-ai` command inside the REPL.

## Activation

```bash
pwn[v0.5.613]:001 >>> pwn-ai
[*] pwn-ai agent TUI activated...
>
```

## Capabilities

- Natural language instruction of complex multi-step security tasks.
- Full tool calling access to:
  - All `PWN::Plugins` (BurpSuite preferred, TransparentBrowser, NmapIt, Shodan, Metasploit, etc.)
  - `PWN::SAST`
  - `PWN::Reports`
  - Shell execution
  - Memory recall / remember
  - Skill usage and distillation
  - Learning / introspection loop
- Persistent context across interactions via memory and skills.

## Tips

- Use `SHIFT+ENTER` to insert newlines.
- `ENTER` submits the prompt.
- Type `back` or `exit` to return to normal REPL.
- Example prompt:
  ```
  Scan https://target with NmapIt + TransparentBrowser (via BurpSuite), 
  run relevant SAST if source present, exploit any findings, generate report.
  ```

## Self-Improvement

Successful workflows can be distilled into reusable **Skills** (see [Skills-Memory-Learning](Skills-Memory-Learning.md)).

See also [AI Integration](AI-Integration.md).

[[Diagrams]]
