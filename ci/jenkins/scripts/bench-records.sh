#!/usr/bin/env sh
# Compares a bench CSV (bench/src/measure.rs format:
# benchmark,unit,samples,median,min,max) with the best median ever seen per
# benchmark, prints one report line each and saves the new bests.
# `ms` is lower-is-better, every other unit (MB/s, ops/s) higher-is-better.
# A median worse than the best by more than BENCH_REGRESSION_PCT percent
# (default 10) is flagged as a regression.
#
# Usage: bench-records.sh <bench.csv> <records.csv>
# records.csv (benchmark,unit,best) is created on the first run.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <bench.csv> <records.csv>" >&2
    exit 84
fi

bench=$1
records=$2
threshold=${BENCH_REGRESSION_PCT:-10}

mkdir -p "$(dirname "$records")"
[ -f "$records" ] || : > "$records"

awk -F, -v threshold="$threshold" -v out="$records.tmp" '
    FILENAME == ARGV[1] { best[$1] = $3; next }
    FNR == 1 { next }
    {
        name = $1; unit = $2; median = $4 + 0
        flag = ""
        if (!(name in best)) {
            record = median
            flag = "first run"
        } else {
            prev = best[name] + 0
            # Positive gain = better, whichever direction the unit goes.
            gain = prev == 0 ? 0 : (median - prev) / prev * 100
            if (unit == "ms") gain = -gain
            if (gain > 0) {
                record = median
                flag = "NEW PB"
            } else {
                record = prev
                if (-gain > threshold) flag = sprintf("REGRESSION %.0f%%", gain)
            }
        }
        printf "%s,%s,%.3f\n", name, unit, record > out
        printf "%-18s %11.3f %-5s best %11.3f %s\n", name, median, unit, record, flag
    }
' "$records" "$bench"

mv "$records.tmp" "$records"
