#!/bin/sh
# Checks the tracked tree before delivery: the Epitech dump and the org mirror
# receive every file tracked on main. Fails on build outputs, temp files,
# secrets, binaries and large files, and on missing Makefile rules.
# The layout rules are in the "Delivery" section of README.md.
set -eu

cd "$(dirname "$0")/.."

# Tracked on purpose although binary and large: the subject itself.
ALLOWED='G-CNA-500-my_pgp.pdf'
MAX_BYTES=524288
EMPTY_TREE=$(git hash-object -t tree /dev/null)

status=0

# Reports each line of $2 as a failure, with $1 as the reason.
report() {
    if [ -n "$2" ]; then
        printf '%s\n' "$2" | while IFS= read -r path; do
            printf 'check_delivery: %s: %s\n' "$1" "$path" >&2
        done
        status=1
    fi
}

# Filters out the paths listed in ALLOWED.
drop_allowed() {
    while IFS= read -r path; do
        case " $ALLOWED " in
            *" $path "*) ;;
            *) printf '%s\n' "$path" ;;
        esac
    done
}

tracked() {
    git -c core.quotepath=off ls-files "$@"
}

report 'build output, temp file or secret' "$(tracked |
    grep -E '(^|/)target/|^my_pgp$|\.(o|a|so|dylib|dll|exe|obj|rlib|rmeta|gcno|gcda|profraw)$|(~|\.swp|\.swo|\.tmp|\.bak|\.orig|\.rej)$|(^|/)(#[^/]*#|\.DS_Store|vgcore\.[0-9]+|\.env)$' ||
    true)"

# Git flags binary files with "-" instead of line counts.
report 'binary file' "$(git -c core.quotepath=off diff --cached --numstat "$EMPTY_TREE" |
    awk -F '\t' '$1 == "-" { print $3 }' |
    drop_allowed)"

report "larger than $MAX_BYTES bytes" "$(tracked -s |
    awk -F '\t' '{ split($1, meta, " "); print meta[2], $2 }' |
    git cat-file --batch-check='%(objectsize) %(rest)' |
    awk -v max="$MAX_BYTES" '$1 > max { sub(/^[0-9]+ /, ""); print }' |
    drop_allowed)"

# Grep as well as make: a rule listed in .PHONY but never defined still dry-runs.
for rule in all re clean fclean; do
    if ! grep -Eq "^${rule}[[:space:]]*:" Makefile || ! make -n "$rule" >/dev/null 2>&1; then
        report 'missing Makefile rule' "$rule"
    fi
done
make -n all 2>/dev/null | grep -q 'my_pgp' || report 'Makefile' "'all' does not build my_pgp"
make -n fclean 2>/dev/null | grep -q 'my_pgp' || report 'Makefile' "'fclean' does not remove my_pgp"

if [ "$status" -ne 0 ]; then
    echo 'check_delivery: FAILED' >&2
    exit 1
fi
echo 'check_delivery: OK'
