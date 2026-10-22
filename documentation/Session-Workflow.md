# Session Workflow

How a `pwn-ai` line is routed, when a goal is considered unfinished, and
which phrases flip those switches. Exact matching lives in
`PWN::AI::Agent::Loop` and `PWN::AI::Agent::OpenGoal`. This page is the
operator cheat sheet.

**See also:** [Sessions](Sessions.md) · [pwn-ai Agent](pwn-ai-Agent.md) ·
[Persistence](Persistence.md)

---

## Life of a line

1. A new activation creates a session; explicit session-picker or CLI resume
   selects an existing stable session ID instead.
2. Cheap intents (greeting, how-to, recall) never open a host-work goal.
3. Everything else is an autonomous goal. `Loop.run` keeps CORE_TOOLS until
   the original request is done or a tool returned failure evidence.
   pwn-ai does not decide authorization.
4. RequestRuntime retains the original objective, amendments, tool evidence and
   verification contract in request/session-bound checkpoints. OpenGoal keeps the
   matching resume pointer; `~/.pwn/open_goal.json` is the legacy global form.
5. Verified completion can clear the matching open goal. Cancellation, failed
   checks or uncertain side effects do not turn unfinished work into success.

```
you type a line
        |
        +-- greeting / how-to / recall -----> short answer, no tools
        |
        +-- continue / resume / keep going --> restore this session's open request
        |
        +-- last / previous session ---------> prior JSONL, not this line
        |
        +-- everything else -----------------> one Loop.run
                                              write? then read it back
                                              listing is not done
```

---

## Unfinished goals

Owner: `PWN::AI::Agent::OpenGoal`, with request-bound persistence and a per-session
pointer. Legacy `~/.pwn/open_goal.json` is accepted only for its matching session.

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
and a trailing `.` / `!`). A new sentence is not a bare resume. Replacing a
checkpointed CLI objective requires `--replace-session ID`, a new prompt/contract
and `--approve-replacement`; the old checkpoint remains unchanged.

`continue scanning the lab` is a new ask, not a resume.

Use `pwn-ai --resume-session EXACT_SESSION_ID` after a process restart. Do not
delete checkpoint files as a recovery shortcut: retain evidence and inspect
uncertain mutations before deciding whether any action is safe to repeat.
`--resume RUN_ID` is TaskDAG resume, not session resume.

---

## This session vs last session

Without explicit resume, entering `pwn-ai` starts a new transcript. "Last session" is the newest other
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
| Write / update / regenerate / docs / fix | Current-turn exact-target host write/readback evidence, matching current bytes and every applicable authored check; an unrelated read or test is insufficient |
| Browser / navigate / `TransparentBrowser` | A **browse** effect (goto / dump_links / close) |
| Hostname / uname / cwd / whoami | Any live **read** |
| Other long goals (bounty, scrape, recon) | **write**, **browse**, or **eval** (`ls` alone is not enough) |

These do **not** count as finishing a write: `memory_remember`,
`learning_note_outcome`, `mistakes_*`, rspec/rubocop green, a README listing,
or "I will do that next time."

After mutation, verify the actual requested target. Literal/artifact checks and
host-authored contracts are stronger than effect categories. Browser activity or
an eval is not by itself proof of arbitrary semantic task completion. Child-agent
prose is not evidence; the parent must accept current exact-target receipts and
rerun its own integration checks. See [Harness Evaluation](Harness-Evaluation.md).

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
| OpenGoal request/session records (legacy `~/.pwn/open_goal.json`) | Unfinished request and matching-session resume pointer |
| `~/.pwn/memory.json` | Durable facts (not "last line") |

[← Home](Home.md)
