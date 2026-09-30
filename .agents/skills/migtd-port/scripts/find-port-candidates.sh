#!/usr/bin/env bash
#
# find-port-candidates.sh — list commits that live on the Microsoft `integration`
# branch but are NOT yet on an intel/main-based target branch, and flag the ones
# that look already-upstreamed so you can skip them.
#
# Why this exists: the majority of `integration` work has already been upstreamed
# to intel/main (in reworded / squashed form), so a naive `git cherry-pick
# base..integration` re-applies dozens of commits that are already present. Patch-id
# (`git cherry`) under-detects because upstreaming refines the patch; commit-message
# similarity is the reliable "already there" signal. This script combines both:
#   - git cherry patch-id membership  (- = identical patch already on target)
#   - subject-similarity vs every target subject (high % = reworded duplicate)
#
# Output is a human-reviewable table. YOU still decide keep/skip per row — treat
# CANDIDATE as "look closer", not "blindly pick".
#
# Usage:
#   ./find-port-candidates.sh [--source REF] [--target REF] [--base REF]
#                             [--threshold N] [--full] [--sql]
#
#   --source REF     branch carrying the changes      (default: origin/integration)
#   --target REF     intel/main-based branch to port onto (default: current branch)
#   --base REF       only consider commits after this  (default: merge-base src/tgt)
#   --threshold N    similarity %% at/above which a row is tagged LIKELY-UPSTREAMED
#                    (default: 55)
#   --full           do not truncate subjects
#   --sql            also emit `INSERT INTO picks ...` lines for the session DB
#
# Exit: 0 always (this is a reporting tool).
set -u
set -o pipefail

SOURCE="origin/integration"
TARGET="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
BASE=""
THRESHOLD=55
FULL=0
EMIT_SQL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --source) SOURCE="$2"; shift 2 ;;
        --target) TARGET="$2"; shift 2 ;;
        --base)   BASE="$2";   shift 2 ;;
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --full)   FULL=1; shift ;;
        --sql)    EMIT_SQL=1; shift ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

git rev-parse --verify "$SOURCE^{commit}" >/dev/null 2>&1 || { echo "bad --source: $SOURCE" >&2; exit 2; }
git rev-parse --verify "$TARGET^{commit}" >/dev/null 2>&1 || { echo "bad --target: $TARGET" >&2; exit 2; }
[ -z "$BASE" ] && BASE="$(git merge-base "$SOURCE" "$TARGET")"
git rev-parse --verify "$BASE^{commit}" >/dev/null 2>&1 || { echo "bad --base: $BASE" >&2; exit 2; }

echo "source : $SOURCE ($(git rev-parse --short "$SOURCE"))"
echo "target : $TARGET ($(git rev-parse --short "$TARGET"))"
echo "base   : $BASE ($(git rev-parse --short "$BASE"))"
echo "thresh : ${THRESHOLD}% subject similarity"
echo

# Candidate commits = base..source, with patch-id membership vs target.
#   git cherry <upstream> <head> <limit>  => examines <limit>..<head>,
#   prefixing '-' if an equivalent patch is already in <upstream>, else '+'.
SRC_TSV="$(mktemp)"; TGT_TSV="$(mktemp)"
trap 'rm -f "$SRC_TSV" "$TGT_TSV"' EXIT

git cherry "$TARGET" "$SOURCE" "$BASE" | while read -r flag sha; do
    printf '%s\t%s\t%s\n' "$flag" "$sha" "$(git show -s --format=%s "$sha")"
done > "$SRC_TSV"

# Target subjects (the already-upstreamed corpus to match against).
git log --format='%H%x09%s' "$BASE..$TARGET" > "$TGT_TSV"

THRESHOLD="$THRESHOLD" FULL="$FULL" EMIT_SQL="$EMIT_SQL" \
python3 - "$SRC_TSV" "$TGT_TSV" <<'PY'
import os, re, sys

thr   = int(os.environ["THRESHOLD"])
full  = os.environ["FULL"] == "1"
emsql = os.environ["EMIT_SQL"] == "1"
src_f, tgt_f = sys.argv[1], sys.argv[2]

PREFIX = re.compile(r'^[a-z]+(\([^)]*\))?!?:\s*')   # strip conventional-commit type(scope):
STOP = set("""a an the to of for in on with and or not is are be add adds added
adding update updates updated use uses using fix fixes fixed feat feature refactor
chore docs test tests style ci build perf migtd support instead into via from this
that when then return returns make makes only also new""".split())

def toks(subj):
    s = PREFIX.sub('', subj.strip().lower())
    s = re.sub(r'[^a-z0-9]+', ' ', s)
    return {w for w in s.split() if w and w not in STOP and len(w) > 2}

def load(path):
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.rstrip('\n')
            if not line:
                continue
            parts = line.split('\t')
            rows.append(parts)
    return rows

tgt = [(h, s, toks(s)) for h, s in load(tgt_f)]

def jaccard(a, b):
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)

def trunc(s, n):
    return s if full or len(s) <= n else s[:n-1] + "\u2026"

rows = load(src_f)
print(f"{'#':>3}  {'SHA':<9} {'PID':<3} {'SIM':>4}  {'SUGGEST':<17} SUBJECT")
print("-" * 100)
seq = 0
sql_lines = []
for r in rows:
    flag, sha = r[0], r[1]
    subj = r[2] if len(r) > 2 else ""
    seq += 1
    short = sha[:9]
    st = toks(subj)
    best, bestsubj = 0.0, ""
    for _, ts, tt in tgt:
        j = jaccard(st, tt)
        if j > best:
            best, bestsubj = j, ts
    simpct = round(best * 100)
    if flag == '-':
        suggest = "SKIP-patchid"          # identical patch already on target
    elif simpct >= thr:
        suggest = "SKIP-similar"          # reworded/squashed duplicate, verify then skip
    else:
        suggest = "CANDIDATE"             # likely genuinely missing — review
    print(f"{seq:>3}  {short:<9} {flag:<3} {simpct:>3}%  {suggest:<17} {trunc(subj,52)}")
    if simpct >= thr and bestsubj:
        print(f"{'':>3}  {'':<9} {'':<3} {'':>4}  {'':<17}   ~ {trunc(bestsubj,70)}")
    if emsql:
        esc = lambda x: x.replace("'", "''")
        status = {'SKIP-patchid':'skip-similar','SKIP-similar':'skip-similar','CANDIDATE':'pick'}[suggest]
        sql_lines.append(
            f"INSERT INTO picks(seq,hash,subject,status,note) VALUES"
            f"({seq},'{sha}','{esc(subj)}','{status}','{esc(bestsubj)}');")

cand = sum(1 for r in rows
           if not (r[0] == '-' ))
print("-" * 100)
print(f"total={len(rows)}  (PID '-' = identical patch already on target; "
      f"SIM >= {thr}% = likely reworded duplicate)")
if emsql and sql_lines:
    print("\n-- session-DB seed (review before trusting 'status'):")
    print("\n".join(sql_lines))
PY
