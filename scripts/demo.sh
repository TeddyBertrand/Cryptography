#!/bin/sh
# Build my_pgp, then run the subject examples of one cryptosystem (or all of
# them), printing each command and its output and failing on a mismatch.
#
#   ./scripts/demo.sh [help|xor|aes|rsa|X25519|pgp-xor|pgp-aes|all]
set -u

usage="usage: $0 [help|xor|aes|rsa|X25519|pgp-xor|pgp-aes|all]"
target=${1:-all}
case "$target" in
    help | xor | aes | rsa | X25519 | pgp-xor | pgp-aes | all) ;;
    *) echo "$usage" >&2; exit 2 ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
echo "Building my_pgp..."
make -C "$root" >/dev/null || { echo "build failed" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ln -s "$root/my_pgp" "$work/my_pgp"
cd "$work"

failures=0

title() {
    printf '\n=== %s ===\n' "$1"
}

# example COMMAND EXPECTED_OUTPUT
example() {
    printf '$> %s\n' "$1"
    actual=$(eval "$1")
    [ -z "$actual" ] || printf '%s\n' "$actual"
    if [ "$actual" != "$2" ]; then
        printf '[FAIL] expected:\n%s\n' "$2"
        failures=$((failures + 1))
    fi
}

xor_key=576861742069732064656164206d6179206e6576657220646965
aes_key=57696e74657220697320636f6d696e67
small_public=0101-19bb
small_private=9d5b-19bb
p=4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1
q=bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb
public=010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3
private=81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3
ciphered_key=97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d
x25519_public=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
x25519_private=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60

demo_help() {
    title "help"
    example './my_pgp -h' "$(sed -n '/^== STDOUT ==$/,/^== STDERR ==$/p' "$root/crates/my_pgp/tests/cases/help.txt" | sed '1d;$d')"
}

demo_xor() {
    title "xor (block)"
    example 'echo "You know nothing, Jon Snow" > message' ''
    example "./my_pgp xor -c -b $xor_key < message > ciphered" ''
    example 'cat -e ciphered' '20070f2700071c6a4449060a490515164e4e12190b190011063c$'
    example "./my_pgp xor -d -b $xor_key < ciphered | cat -e" 'You know nothing, Jon Snow$'
}

demo_aes() {
    title "aes (block)"
    example 'echo "All men must die" > message' ''
    example "./my_pgp aes -c -b $aes_key < message > ciphered" ''
    example 'cat -e ciphered' '744ce22c385958348f0df26eceb62eef$'
    example "./my_pgp aes -d -b $aes_key < ciphered | cat -e" 'All men must die$'

    title "aes (stream, no -b)"
    example 'echo "You know nothing, Jon Snow" > message' ''
    example "./my_pgp aes -c $aes_key < message > ciphered" ''
    example 'cat -e ciphered' 'd52172daa46769ff74c9d9e56e328aed1de92dfee2113583a7c7023341a19db8$'
    example "./my_pgp aes -d $aes_key < ciphered | cat -e" 'You know nothing, Jon Snow$'
}

demo_rsa() {
    title "rsa (small keys)"
    example "./my_pgp rsa -g d3 e3" "public key: $small_public
private key: $small_private"
    example "echo WF | ./my_pgp rsa -c $small_public" '8f84'
    example "echo 8f84 | ./my_pgp rsa -d $small_private" 'WF'

    title "rsa (large keys)"
    example "./my_pgp rsa -g $p $q" "public key: $public
private key: $private"
    example "echo 'The night is dark and full of terrors' | ./my_pgp rsa -c $public" '445b349e7318ad6af16b0bbb718be88ba1c41751f95751cd58857f88fe31f970405c6ec3f16d79172543bf4e571b5596d212f3e79cd08ef14abd244e325b80'
    example "echo 445b349e7318ad6af16b0bbb718be88ba1c41751f95751cd58857f88fe31f970405c6ec3f16d79172543bf4e571b5596d212f3e79cd08ef14abd244e325b80 | ./my_pgp rsa -d $private" 'The night is dark and full of terrors'
}

demo_x25519() {
    title "X25519"
    example "echo 'Winter is coming' | ./my_pgp X25519 -c $x25519_public | ./my_pgp X25519 -d $x25519_private" 'Winter is coming'
}

demo_pgp_xor() {
    title "pgp-xor"
    example "echo 'Winter is coming' | ./my_pgp pgp-xor -c -b $aes_key:$public" "$ciphered_key
300707190a11001a1a00110a19070730"
    example "echo 300707190a11001a1a00110a19070730 | ./my_pgp pgp-xor -d -b $ciphered_key:$private" 'Winter is coming'
}

demo_pgp_aes() {
    title "pgp-aes"
    example "echo 'All men must die' | ./my_pgp pgp-aes -c -b $aes_key:$public" "$ciphered_key
744ce22c385958348f0df26eceb62eef"
    example "echo 744ce22c385958348f0df26eceb62eef | ./my_pgp pgp-aes -d -b $ciphered_key:$private" 'All men must die'
}

case "$target" in
    help) demo_help ;;
    xor) demo_xor ;;
    aes) demo_aes ;;
    rsa) demo_rsa ;;
    X25519) demo_x25519 ;;
    pgp-xor) demo_pgp_xor ;;
    pgp-aes) demo_pgp_aes ;;
    all)
        demo_help
        demo_xor
        demo_aes
        demo_rsa
        demo_x25519
        demo_pgp_xor
        demo_pgp_aes
        ;;
esac

if [ "$failures" -ne 0 ]; then
    printf '\n%s example(s) failed\n' "$failures"
    exit 1
fi
