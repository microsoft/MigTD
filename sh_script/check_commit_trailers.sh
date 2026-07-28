#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <base-commit> <head-commit>" >&2
    exit 2
fi

BASE_COMMIT="$1"
HEAD_COMMIT="$2"

git rev-parse --verify "${BASE_COMMIT}^{commit}" >/dev/null
git rev-parse --verify "${HEAD_COMMIT}^{commit}" >/dev/null

# AI assistance belongs in Assisted-by. Match explicit agent display names and
# bot-like mailbox names rather than vendor domains, which humans may use.
AI_DISPLAY_NAME_PATTERN='^((github[[:space:]]+)?copilot([[:space:]]+(cli|agent))?|chatgpt|claude[[:space:]]+(code|ai|agent|bot)|gemini([[:space:]]+(ai|agent|bot|cli))?|cursor[[:space:]]+(agent|ai|bot)|codeium([[:space:]]+(agent|ai|bot))?|devin[[:space:]]+(agent|ai|bot)|amazon[[:space:]]+q([[:space:]]+developer)?|q[[:space:]]+developer)([^[:alnum:]]|$)'
AI_BOT_EMAIL_PATTERN='<[^>]*(copilot|chatgpt|claude[-_.]?(code|ai|agent|bot)|gemini[-_.]?(ai|agent|bot)?|cursor[-_.]?(agent|ai|bot)|codeium|devin[-_.]?(agent|ai|bot)|amazon[-_.]?q|q[-_.]?developer)@'
FAILED=0

parse_commit_trailers() {
    local commit="$1"
    local start
    local found_trailer=0
    local line
    local index
    local -a lines

    mapfile -t lines < <(git show -s --format=%B "$commit")
    start=${#lines[@]}

    # GitHub recognizes authorship trailers separated by blank lines, while
    # `git interpret-trailers --parse` expects a contiguous trailer block.
    # Isolate the trailer-like suffix and remove only its blank separators
    # before asking Git to normalize keys, spacing, and continuation lines.
    for ((index = ${#lines[@]} - 1; index >= 0; index--)); do
        line="${lines[index]}"
        if [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]] ||
              "$line" =~ ^[[:alnum:]][[:alnum:]-]*[[:space:]]*: ]]; then
            start=$index
            if [[ "$line" =~ ^[[:alnum:]][[:alnum:]-]*[[:space:]]*: ]]; then
                found_trailer=1
            fi
        else
            break
        fi
    done

    if [[ "$found_trailer" -eq 0 ]]; then
        return 0
    fi

    {
        printf 'commit message\n\n'
        for ((index = start; index < ${#lines[@]}; index++)); do
            if [[ ! "${lines[index]}" =~ ^[[:space:]]*$ ]]; then
                printf '%s\n' "${lines[index]}"
            fi
        done
    } | git interpret-trailers --parse
}

while IFS= read -r COMMIT; do
    OFFENDING_TRAILERS=""
    while IFS= read -r TRAILER; do
        KEY="${TRAILER%%:*}"
        VALUE="${TRAILER#*:}"
        KEY="${KEY,,}"
        if [[ "$KEY" != "signed-off-by" && "$KEY" != "co-authored-by" ]]; then
            continue
        fi
        MATCH_VALUE="${VALUE#"${VALUE%%[![:space:]]*}"}"
        MATCH_VALUE="${MATCH_VALUE#\"}"
        MATCH_VALUE="${MATCH_VALUE#\'}"
        if grep -Eiq "${AI_DISPLAY_NAME_PATTERN}|${AI_BOT_EMAIL_PATTERN}" <<<"$MATCH_VALUE"; then
            OFFENDING_TRAILERS+="${TRAILER}"$'\n'
        fi
    done < <(parse_commit_trailers "$COMMIT")

    if [[ -n "$OFFENDING_TRAILERS" ]]; then
        echo "Error: commit $(git show -s --format='%h %s' "$COMMIT") attributes authorship to an AI tool:" >&2
        printf '%s' "$OFFENDING_TRAILERS" >&2
        echo "Use an Assisted-by trailer instead; only humans may appear in Signed-off-by or Co-authored-by." >&2
        FAILED=1
    fi
done < <(git rev-list --reverse "${BASE_COMMIT}..${HEAD_COMMIT}")

exit "$FAILED"
