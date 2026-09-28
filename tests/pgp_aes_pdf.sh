#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

symmetric_key=57696e74657220697320636f6d696e67
public_key=010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3
private_key=81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3
ciphered_key=97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d
ciphertext=744ce22c385958348f0df26eceb62eef

printf '%s\n' 'All men must die' |
    cargo run --quiet --package my_pgp -- pgp-aes -c -b "$symmetric_key:$public_key"
printf '%s\n' "$ciphertext" |
    cargo run --quiet --package my_pgp -- pgp-aes -d -b "$ciphered_key:$private_key"
printf '\n'
