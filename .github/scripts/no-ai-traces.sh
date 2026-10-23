#!/usr/bin/env bash
#
# Fail if AI tooling attribution appears anywhere in the history.
#
# The repository's public face carries no AI tooling attribution: commits and
# tracked files read as ordinary engineering work, and the local-only notes
# (CLAUDE.md, local/) never become tracked. The history is still small and not
# yet published, so the whole of it is checked on every run rather than only
# the change under review: a trace that slipped in once has to be rewritten out
# before the first push, not grandfathered.
#
# What is matched is attribution, not the mere mention of a tool: a trailer
# naming an assistant, a "generated with/by <assistant>" line, the vendor
# no-reply address, the robot-emoji footer, links to the assistant's site.
# A bare tool name is not enough: .gitignore must be able to name CLAUDE.md
# precisely so that it stays untracked.
#
# Usage:
#   no-ai-traces.sh [REV]       check every commit reachable from REV (HEAD):
#                               messages, added lines, file paths; plus the
#                               PR_TITLE / PR_BODY environment variables
#   no-ai-traces.sh --message   check a commit message read from stdin
#   no-ai-traces.sh --diff      check the added lines of a unified diff read
#                               from stdin
#
# Exit status: 0 clean, 1 a trace was found, 2 usage or repository error.

set -uo pipefail
export LC_ALL=C

SELF_PATH='.github/scripts/no-ai-traces.sh'

# Assistants and their vendors, as they appear in attribution lines.
AI='(claude|anthropic|chatgpt|openai|gpt-?[0-9o]|copilot|gemini|codex|cursor|devin|aider|windsurf|codeium|tabnine|llm)'

PATTERN="co-authored-by:.*\\b${AI}"
PATTERN+="|@(anthropic|openai)\\.com\\b"
PATTERN+="|\\b(generated|written|created|authored|co-?authored|assisted|produced|made)[[:space:]]+(with|by|using|via|in)[[:space:]]+\\[?${AI}"
PATTERN+="|🤖[[:space:]]*generated"
PATTERN+="|claude\\.(ai|com)/(code|claude-code)"
PATTERN+="|\\bclaude[ -]code\\b"
PATTERN+="|\\bai[ -](generated|assisted|written)\\b"

# Paths that must never be tracked: the assistants' instruction and state
# files, and the local-only notes directory.
FORBIDDEN_PATHS='(^|/)(claude\.md|agents\.md|gemini\.md|\.cursorrules)$|(^|/)\.(claude|cursor|aider[^/]*)(/|$)|^local/'

status=0
fail() { printf '::error::%s\n' "$1"; status=1; }
die() { echo "$1" >&2; exit 2; }

# The matchers only print; report() runs in this shell (fed by process
# substitution, never at the end of a pipeline) so that fail() can set status.

# stdin: free text. Prints matching lines, returns 0 if any.
match_text() { grep -inE "$PATTERN"; }

# stdin: unified diff. Prints matching added lines, returns 0 if any.
# File headers ("+++ b/path", "+++ /dev/null") are not content.
match_added() {
    grep -E '^\+' | grep -vE '^\+\+\+ (b/|/dev/null)' | grep -iE "$PATTERN"
}

report() { # $1 = message; stdin = hits
    local hits
    hits=$(cat)
    [ -z "$hits" ] && return 0
    fail "$1"
    printf '%s\n' "$hits" | head -5 | sed 's/^/    /'
}

finish() {
    if [ "$status" -eq 0 ]; then
        echo "no AI tooling attribution found ($1)"
    fi
    exit "$status"
}

case "${1:-}" in
    --message)
        report "commit message carries AI tooling attribution:" < <(match_text)
        finish "message from stdin"
        ;;
    --diff)
        report "diff adds a line carrying AI tooling attribution:" < <(match_added)
        finish "diff from stdin"
        ;;
    -h | --help)
        sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
        exit 0
        ;;
    -*)
        echo "unknown option: $1" >&2
        exit 2
        ;;
esac

REV="${1:-HEAD}"

git rev-parse --verify --quiet "${REV}^{commit}" >/dev/null || die "not a commit: $REV"
[ "$(git rev-parse --is-shallow-repository)" = "false" ] \
    || die "shallow clone: the whole history is needed (fetch-depth: 0)"

# 1. Paths ever added to the history.
while IFS= read -r path; do
    [ -n "$path" ] && fail "path must stay local and untracked: $path"
done < <(git log --format= --name-only --no-renames "$REV" | sort -u | grep -iE "$FORBIDDEN_PATHS")

# 2. and 3. Every commit's message, and every line it adds. Merges are
# diffed against each parent so that a line introduced while resolving a
# conflict is seen too. This script is exempt from the line scan: it
# necessarily spells out the patterns.
count=0
while IFS= read -r sha; do
    count=$((count + 1))
    short=$(git rev-parse --short "$sha")
    subject=$(git log -1 --format=%s "$sha")
    message=$(git log -1 --format=%B "$sha") || die "cannot read commit $sha"
    diff=$(git show -m --format= --no-color --no-ext-diff --no-renames "$sha" \
        -- . ":(exclude)$SELF_PATH") || die "cannot diff commit $sha"
    report "commit $short ($subject): message carries AI tooling attribution:" \
        < <(printf '%s\n' "$message" | match_text)
    report "commit $short ($subject): adds a line carrying AI tooling attribution:" \
        < <(printf '%s\n' "$diff" | match_added)
done < <(git rev-list "$REV")

# 4. Pull request title and body, passed through the environment by the
# workflow (never interpolated into a shell command).
for field in PR_TITLE PR_BODY; do
    value="${!field-}"
    [ -z "$value" ] && continue
    report "pull request ${field#PR_} carries AI tooling attribution:" \
        < <(printf '%s\n' "$value" | match_text)
done

finish "$count commits from $REV"
