# AES (Advanced Encryption Standard)

[← Guide index](../README.md) · Math and code: [deep dive](../deep-dive/aes.md) · Crate: [aes](../crates/aes.md) · Security: [defense.md § AES](../../defense.md#aes)

## In one sentence

The world's standard symmetric cipher: it scrambles 16 bytes at a time with a key, so
thoroughly that only the same key can unscramble them.

## The picture

Think of shuffling a deck of 16 cards, the same recipe repeated 10 to 14 times (a **round**).
Each round does four simple moves:

| Move | What it does | Why |
|---|---|---|
| **SubBytes** | replace each byte using a fixed substitution rule | the only non-linear step: without it AES would be simple equations to solve |
| **ShiftRows** | slide the rows of the 4×4 grid sideways | moves bytes into other columns |
| **MixColumns** | blend the 4 bytes of each column together | one changed byte changes the whole column |
| **AddRoundKey** | flip bits with a key derived for this round | this is where the secret comes in |

After just two rounds, changing one bit of the message changes about half of the output.
Every move can be undone, so deciphering runs the moves backwards.

The key itself (16, 24 or 32 bytes) is stretched once into one sub-key per round.

## How it works in my_pgp

- Block mode (`-b`): exactly one 16-byte block.
- Stream mode: cut the message into 16-byte blocks, pad the last one with zeros, cipher each
  block on its own (this is called **ECB**).

```
$ echo 'All men must die' | ./my_pgp aes -c -b 57696e74657220697320636f6d696e67
744ce22c385958348f0df26eceb62eef
```

## Is it secure?

- **AES itself: yes.** After 25 years of study, nothing beats trying every key, and 2^128 keys
  is out of reach.
- **ECB mode: leaks patterns.** Two identical blocks of message give two identical blocks of
  ciphertext (the famous "ECB penguin" picture still shows the penguin).
- **Our implementation avoids timing leaks**: the usual lookup table for SubBytes can reveal
  the key through CPU cache timing, so we compute it with logic gates instead.

## Going further

The [deep dive](../deep-dive/aes.md) covers the byte math (GF(2^8)), the key expansion, the
optimised MixColumns and the bitsliced constant-time S-box.
