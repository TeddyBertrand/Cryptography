#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

key=576861742069732064656164206d6179206e6576657220646965
ciphertext=20070f2700071c6a4449060a490515164e4e12190b190011063c

printf '%s\n' 'You know nothing, Jon Snow' |
    cargo run --quiet --package my_pgp -- xor -c -b "$key"
printf '\n'
printf '%s\n' "$ciphertext" |
    cargo run --quiet --package my_pgp -- xor -d -b "$key"
printf '\n'
