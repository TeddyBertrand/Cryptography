#!/usr/bin/env sh
# Groups the results of a nextest JUnit report by theme, for the Discord build report.
#
# Prints one tab-separated line per theme: `THEME <group> <name> <passed> <failed> <skipped>`,
# then one `FAIL <test>` line per failing test. Groups, in print order:
#   functional  one theme per tests/cases family, from the module in the test name (xor::...)
#   roundtrip   property tests (crates/my_pgp/tests/roundtrip)
#   integration the other my_pgp test binaries (args, aes, rsa, x25519, xor)
#   unit        the unit tests of every other crate, one theme per crate
#
# Usage: test-themes.sh <junit.xml>
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <junit.xml>" >&2
    exit 84
fi

# The report is split on `<`, so each record is one tag whatever the indentation.
awk -v RS='<' '
    function attr(tag, key,    rest, start) {
        start = index(tag, " " key "=\"")
        if (!start) return ""
        rest = substr(tag, start + length(key) + 3)
        return substr(rest, 1, index(rest, "\"") - 1)
    }
    function settle(    group, name, module) {
        if (suite == "my_pgp::functional") {
            group = "functional"
            module = index(tname, "::")
            name = module ? substr(tname, 1, module - 1) : "cli"
        } else if (suite == "my_pgp::roundtrip") {
            group = "roundtrip"; name = "roundtrip"
        } else if (suite ~ /^my_pgp::/) {
            group = "integration"; name = substr(suite, 9)
        } else {
            group = "unit"; name = suite
        }
        key = group SUBSEP name
        if (!(key in seen)) { seen[key] = 1; order[++themes] = key }
        if (state == "fail") { failed[key]++; failures[++fails] = suite "::" tname }
        else if (state == "skip") skipped[key]++
        else passed[key]++
        open = 0
    }
    {
        tag = $0
        sub(/^[ \t\r\n]+/, "", tag)
        split(tag, words, /[ \t\r\n>]/)
        kind = words[1]
        sub(/\/$/, "", kind)
        if (kind == "testsuite") suite = attr(tag, "name")
        else if (kind == "testcase") {
            tname = attr(tag, "name"); state = "pass"; open = 1
            if (tag ~ /\/>[ \t\r\n]*$/) settle()
        }
        else if (kind == "failure" || kind == "error") { if (open) state = "fail" }
        else if (kind == "skipped") { if (open && state != "fail") state = "skip" }
        else if (kind == "/testcase") { if (open) settle() }
    }
    END {
        split("functional roundtrip integration unit", groups, " ")
        for (g = 1; g <= 4; g++)
            for (t = 1; t <= themes; t++) {
                split(order[t], parts, SUBSEP)
                if (parts[1] != groups[g]) continue
                printf "THEME\t%s\t%s\t%d\t%d\t%d\n", parts[1], parts[2], passed[order[t]], failed[order[t]], skipped[order[t]]
            }
        for (f = 1; f <= fails; f++) printf "FAIL\t%s\n", failures[f]
    }
' "$1"
