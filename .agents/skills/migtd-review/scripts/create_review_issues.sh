#!/usr/bin/env bash
# Template: create+close GH issues from a directory of body files.
# Body files: body_000.md ... body_NNN.md (each starts with "# <title>" on line 1)
# Each body file may end with a marker line "STATUS: closed/<reason>" or "STATUS: open"
#
# Expected env:
#   REPO   - e.g. "Microsoft/MigTD"
#   PREFIX - title prefix, defaults to "[Copilot Review]"
#
# Notes:
# - Auth: `gh auth login --hostname github.com --web` first (device flow).
# - SSO: SAML may require `gh auth refresh -s repo,write:org`.
# - EMU accounts cannot create issues — use a personal account.
# - `gh issue close --reason "not planned"` (with space).

set -euo pipefail

: "${REPO:?Set REPO=<owner>/<repo>}"
PREFIX="${PREFIX:-[Copilot Review]}"
BODY_DIR="${BODY_DIR:-.copilot-review-issues}"

if [[ ! -d "$BODY_DIR" ]]; then
    echo "Body dir not found: $BODY_DIR" >&2
    exit 1
fi

for body in "$BODY_DIR"/body_*.md; do
    [[ -f "$body" ]] || continue
    title_line=$(head -n1 "$body")
    title="${title_line#"# "}"
    full_title="$PREFIX $title"

    echo "→ Creating: $full_title"
    issue_url=$(gh issue create --repo "$REPO" --title "$full_title" --body-file "$body")
    echo "  $issue_url"

    # Look at last line for STATUS marker
    status_line=$(tail -n1 "$body")
    case "$status_line" in
        "STATUS: closed/fixed")
            gh issue close "$issue_url" --reason "completed" --comment "Fixed in linked commit." ;;
        "STATUS: closed/wont-fix")
            gh issue close "$issue_url" --reason "not planned" --comment "Wont-fix: see triage notes." ;;
        "STATUS: closed/false-positive")
            gh issue close "$issue_url" --reason "not planned" --comment "False-positive: see triage notes." ;;
        *) ;;
    esac
done
