---
type: Playbook
title: Agent Notes — MigTD
description: The always-read entry point — session-start/end ritual and links to every topical knowledge file. Read this first.
tags: [entry-point, workflow, living-document]
timestamp: 2026-07-13T22:37:00+00:00
---

# Agent Notes — MigTD

**Read this before doing anything in this repo.** These are facts and
conventions that have had to be repeated across many sessions by past
contributors. Adopting them up-front avoids rounds of correction.

The authoritative deep reference is `.agents/skills/migtd-review/SKILL.md`.
This file is the **entry point** into the rest of `.agents/knowledge/` — it
intentionally stays short; each linked file covers one topic in depth.

> **Living document.** This knowledge base is intended to accumulate
> institutional knowledge over time, contributed by both human collaborators
> and AI agents. See "Reflect and update" below — every agent should reread
> these notes at session start and propose updates at session end if
> something non-obvious was learned.

---

## Knowledge index

See [.agents/index.md](index.md) for the full bundle index. Directly
relevant to every session:

* [Commit Hygiene, Remotes & Workflow Patterns](knowledge/commit-and-workflow.md)
* [Setup, Verification Gauntlet & Pre-done Checklist](knowledge/verification-and-checklist.md)
* [MigTD Domain Facts](knowledge/domain-facts.md) — trust model, attestation, transport, heap
* [Code Style Preferences](knowledge/code-style.md)
* [Anti-patterns — Things To NOT Do](knowledge/anti-patterns.md)
* [Engineering Decisions Log](knowledge/decisions-log.md)

## Reflect and update these notes

**Every agent must reread this knowledge base at session start, and reflect
on it at session end.** If during the session you:

- got corrected by a human collaborator on something that wasn't already
  written here,
- discovered a non-obvious architectural fact (especially one that
  contradicts a naive reading of the code),
- identified a rejected hypothesis worth recording,
- learned a workflow shortcut, repo-specific gotcha, or environment
  requirement,
- found that an entry here is now stale or wrong,

…then **update the relevant file as part of your session output** (a
separate small commit, with sign-off, is fine — message it as
`docs(agents): …`). Keep edits lean:

- Add the smallest faithful note, not an essay, to the **topical** file it
  belongs in (see the index above) — don't pile everything back into this
  entry-point file.
- Cite a commit SHA, file:line, or test name when it helps a future reader
  verify the claim.
- If you remove an entry, briefly note why in the commit message — it
  protects against thrashing.
- If a fact is highly task-specific or temporary (e.g. "for the current PR,
  skip X"), it does **not** belong here — keep it in your session state.
- If a new topic doesn't fit an existing file, add a new file under
  `.agents/knowledge/` with OKF frontmatter (`type`, `title`, `description`)
  and link it from `.agents/index.md` and this file's index above.

If a backup mechanism is available in your environment (e.g. a session-state
folder outside the repo), keep a copy of this file there before any risky
operation like `git clean -fdx`.

The goal: a newcomer agent reading this file should be able to skip the
classes of mistakes their predecessors have made.
