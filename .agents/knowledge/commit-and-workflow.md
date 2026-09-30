---
type: Playbook
title: Commit Hygiene, Remotes & Workflow Patterns
description: DCO sign-off rules, commit/force-push discipline, remote layout, common rebase/cherry-pick workflow patterns, and issue/PR filing conventions.
tags: [git, commit-hygiene, remotes, workflow, issues]
timestamp: 2026-07-10T19:26:55+00:00
---

# Commit Hygiene, Remotes & Workflow Patterns

> Condensed in the root [agent guide](../../AGENTS.md).

## Commit hygiene

- **Always commit with `git commit -s`** (or manually add the
  `Signed-off-by:` trailer using the current `git config user.name` and
  `user.email`). The project requires DCO sign-off on every committable
  change **except** debug-only or `REVERTME` test commits.
- Use the existing repo identity — do not invent a different author. If the
  Copilot `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`
  trailer is appropriate for your environment, include it **in addition to**
  the human Signed-off-by, not instead of it.
- **Commit message style: brief.** One short subject line stating the
  problem, then a short body describing the high-level solution. Skip filler
  like "no behavioural changes" boilerplate unless it materially helps a
  future reader.
- **Don't bundle unrelated changes** into one commit. Separate:
  - behaviour change vs refactor → two commits (or `fixup`/`squash` later);
  - pre-existing fmt/lint fix vs your fix → standalone commit with a
    "pre-existing; not caused by this series" note.
- **Fold/squash freely with `git rebase -i`** (`fixup` for "absorb and drop my
  message", `squash` for "absorb and keep my message"). This is requested
  often during cleanup.
- **Force-push** only to a personal fork remote (e.g. `origin`), and only
  with `--force-with-lease=<branch>:<known-sha>`. Never force-push to
  `intel/*` or `ms/*` / `upstream/*` remotes.

## Remotes & branches

Typical remote layout in active checkouts:

```
intel    https://github.com/intel/MigTD.git        # Intel upstream
ms       https://github.com/microsoft/MigTD.git    # Microsoft fork
upstream https://github.com/microsoft/MigTD.git    # alias for ms
origin   https://github.com/<personal>/MigTD.git   # personal fork (push target)
```

- "Upstream" in conversation usually means **`intel/main`** when discussing
  Intel-bound patches, and **`microsoft/main`** (a.k.a. `ms/main` /
  `upstream/main`) when discussing the Microsoft fork. Confirm by context.
- **Microsoft-specific features kept out of Intel-bound patches** include
  `use-mock-quote`, AzCVMEmu emulation, and allow-all policy. Consult the
  [migtd-port skill](/skills/migtd-port/SKILL.md) when rebasing toward Intel.

## Common workflow patterns

- **Rebase onto upstream**: "rebase changes from `<SHA>` onto
  `origin/<branch>`. Discard changes already on that branch." Use
  `git rebase --onto`.
- **Cherry-pick from `intel/main` to simplify**: when bringing in fixes from
  Intel, prefer cherry-pick over re-implementation if the change is small.
- **Squash/fold during cleanup**: commits are often named by target SHA
  ("fold into `<sha>`", "fixup for `<sha>`"). Use `git rebase -i` with
  `fixup` / `squash`.
- **Reference-by-commit**: when a specific SHA is cited as a template, read
  that commit's diff before re-implementing.
- **Resume from a previous session checkpoint**: the session_store DB has
  `checkpoints` keyed by session title — search there.

## Issue / PR filing

- GH issue title prefix: **`[Copilot Review]`** (not `[Security]` — not all
  findings are security).
- **Microsoft EMU (Enterprise Managed User) GH accounts cannot create
  issues on external repos.** Use a personal GH account via
  `gh auth login --hostname github.com --web`. Verify with `gh auth status`
  before running any issue-creation script.
- `gh issue close --reason "not planned"` (literal space, *not*
  `not_planned`).
- See [`create_review_issues.sh`](/skills/migtd-review/scripts/create_review_issues.sh)
  for the template.
