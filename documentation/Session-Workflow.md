# Session Workflow

How a `pwn-ai` line is routed, when a goal is considered unfinished, and
which phrases flip those switches. Exact matching lives in
`PWN::AI::Agent::Loop` and `PWN::AI::Agent::OpenGoal`. This page is the
operator cheat sheet.

**See also:** [Sessions](Sessions.md) · [pwn-ai Agent](pwn-ai-Agent.md) ·
[Persistence](Persistence.md)

---

## Life of a line

1. Entering `pwn-ai` always creates a **new** `~/.pwn/sessions/<timestamp>_<hex>.jsonl`.
2. Cheap intents (greeting, how-to, recall) never open a host-work goal.
3. Everything else is an autonomous goal. `Loop.run` keeps CORE_TOOLS until
   the original request is done or truly blocked.
4. An unfinished host-work request is written to `~/.pwn/open_goal.json`.
5. An accepted final answer deletes that file. Budget exhaust leaves it.

```
you type a line
        |
        +-- greeting / how-to / recall -----> short answer, no tools
        |
        +-- continue / resume / keep going --> reload open_goal.json
        |
        +-- last / previous session ---------> prior JSONL, not this line
        |
        +-- everything else -----------------> one Loop.run
                                              write? then read it back
                                              listing is not done
```

---

## Unfinished goals

File: `~/.pwn/open_goal.json` (`PWN::AI::Agent::OpenGoal`).

| You type (whole line) | Effect |
|---|---|
| `continue` | Reload the saved request and keep working |
| `resume` | same |
| `keep going` | same |
| `pick up` | same |
| `carry on` | same |
| `continue please` | same |
| `resume the goal` / `resume the task` / `resume work` | same |

The line must be **only** that phrase (optional `please` / `the goal|task|work`
and a trailing `.` / `!`). A new sentence is a new goal and **replaces** the
saved request.

`continue scanning the lab` is a new ask, not a resume.

Delete `~/.pwn/open_goal.json` to drop a stuck checkpoint.

---

## This session vs last session

Entering `pwn-ai` is a new transcript. "Last session" is the newest other
`~/.pwn/sessions/*.jsonl`.

| Phrase | Where it reads |
|---|---|
| `what did I just say?` | **This** session |
| `what did I just ask?` / `what was my last request?` | this session |
| `how did you respond?` / `what did you just say?` | this session |
| `what did I just say in the last session?` | **Previous** JSONL |
| `in the last session` / `previous session` / `prior session` | previous JSONL |
| `session_recall` (tool) | older transcripts, skips the current id |

If there is no previous file: `I do not have a previous session transcript yet.`

---

## Cheap short-circuits (no tools)

Whole-line greetings only, so `hi, scan this host` stays a goal:

| Trigger | Examples |
|---|---|
| Greeting | `hi` `hello` `hey` `howdy` `yo` `good morning` |
| How-to | `how to` `how do I` `how can I` `syntax for` `usage of` `man page` |
| Recall | table above |

---

## Host work stays open until the artefact is checked

| Need | Done only when |
|---|---|
| Write / update / regenerate / docs / fix | A **write** effect, then a later **read** (`cat`, `ruby -c`, eval read) |
| Browser / navigate / `TransparentBrowser` | A **browse** effect (goto / dump_links / close) |
| Hostname / uname / cwd / whoami | Any live **read** |
| Other long goals (bounty, scrape, recon) | **write**, **browse**, or **eval** (`ls` alone is not enough) |

These do **not** count as finishing a write: `memory_remember`,
`learning_note_outcome`, `mistakes_*`, rspec/rubocop green, a README listing,
or "I will do that next time."

After you mutate a file, read it back before a final.

---

## Phrases that are **not** a final answer

Loop keeps calling tools if the model emits any of:

- `shall I` / `should I` / `want me to` / `proceed?` / `continue?`
- `# Remaining block` / heading-only outlines
- `were not applied` / `not written to disk` / `next time`
- narrated next tool (`Wait, let's try...`) with no `tool_calls`

Type `continue` yourself only to resume a **saved** open goal after the REPL
died. Do not use it as a mid-turn "ok, go on" - the loop should already be
going.

---

## Files

| Path | Role |
|---|---|
| `~/.pwn/sessions/<id>.jsonl` | This activation's transcript |
| `~/.pwn/open_goal.json` | Unfinished host-work request |
| `~/.pwn/memory.json` | Durable facts (not "last line") |

[← Home](Home.md)
