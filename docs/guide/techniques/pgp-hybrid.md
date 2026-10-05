# PGP hybrid encryption (`pgp-xor`, `pgp-aes`)

[← Guide index](../README.md) · Math and code: [deep dive](../deep-dive/pgp-hybrid.md) · Crate: [pgp](../crates/pgp.md) · Security: [defense.md § PGP](../../defense.md#pgp-pgp-xor-pgp-aes)

## In one sentence

Lock the message with a fast symmetric key, then lock that small key with RSA: best of both.

## The picture

- **Symmetric** (XOR, AES): fast, any length, but both sides must already share the key.
- **RSA**: no shared secret needed, but slow and only fits a small number.

So do what PGP, HTTPS and email encryption do: put the message in a safe (AES), and send the
safe's key in an RSA padlock.

```
cipher:    line 1 = RSA(symmetric key)        ← small, RSA runs once
           line 2 = AES or XOR(message)       ← the bulk, fast
decipher:  RSA-unlock line 1 → symmetric key → unlock line 2
```

## How it works in my_pgp

The key argument joins both keys with `:`.

```
$ echo 'All men must die' | ./my_pgp pgp-aes -c -b "57696e74657220697320636f6d696e67:$PUBLIC"
97f2af4c…d149d41d                    ← the AES key, ciphered with RSA
744ce22c385958348f0df26eceb62eef     ← the message, ciphered with AES
```

To decipher, pass line 1 with the private key (`CIPHERED_KEY:d-n`) and line 2 on stdin.

One quirk: textbook RSA treats the key as a number, so trailing zero bytes get lost
(`aabb00` comes back as `aabb`). my_pgp restores the length when it can, refuses keys it
couldn't restore, and `-p` (OAEP) avoids the problem entirely.

## Is it secure?

The design, yes: it's how real-world encryption works. Here it inherits the weaknesses of its
parts: textbook RSA without `-p`, XOR or AES in ECB mode, and no integrity check.

## Going further

The [deep dive](../deep-dive/pgp-hybrid.md) details the trailing-zero rules per mode and the
code.
