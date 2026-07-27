# Why PWN

## The problem

Offensive security is a **toolchain problem**. One engagement may touch
`nmap`, `burp`, `msfconsole`, a headless browser, `adb`, `gqrx`, three cloud
consoles, a fuzzer, `radare2`, a spreadsheet of findings, and a bug-bounty
form. Each tool has its own config, its own output format, and its own idea
of what a "target" is. Gluing them together is most of the job - and that
glue gets rewritten, badly, on every engagement.

LLM agents are strong at *planning* attack chains, but they still need a
reliable, auditable way to *run* those steps on a real host.

## The design bet

PWN bets that the right abstraction is **plain Ruby methods with a uniform
`opts = {}` signature**, exposed at the same time to:

- a human in a REPL,
- an LLM in a tool-calling loop,
- a shell script in CI,
- a cron job at 3 am.

Because every capability is a method, the same line of code works in all four
places. Because every method is open-source Ruby, you can read it - which is
critical when the caller is an autonomous agent.

## Why open primitives matter

| Closed / black-box | PWN |
|---|---|
| "Trust our scanner" | `cat lib/pwn/sast/sql.rb` - read the regex yourself |
| Per-seat license for the glue | MIT-licensed glue; bring your own Burp Pro / Nessus key |
| Agent output is a PDF | Agent output is a `PWN::Reports` object *and* a distilled skill *and* a memory entry |
| One vendor's model | Five interchangeable engines; swarm can pit them against each other |

## Why the feedback loop matters

A pentest framework that does not learn repeats the same dead-end scans
forever. PWN records **per-tool success rate**, **per-task outcome**, **host
drift**, and **external CVE intel**, then correlates them so tomorrow's run
can start where today's left off. See
[Skills, Memory & Learning](Skills-Memory-Learning.md),
[Reinforcement Learning](Reinforcement-Learning.md), and
[Extrospection](Extrospection.md).

**Next:** [How PWN Works](How-PWN-Works.md)

[← Home](Home.md)
