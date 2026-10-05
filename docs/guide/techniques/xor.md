# XOR cipher

[← Guide index](../README.md) · Math and code: [deep dive](../deep-dive/xor.md) · Crate: [xor](../crates/xor.md) · Security: [defense.md § XOR](../../defense.md#xor)

## In one sentence

Flip some bits of the message, chosen by the key; flipping the same bits again gives the
message back.

## The picture

Think of the key as a stencil laid over the message. Wherever the stencil has a hole (a `1`
bit), the message bit is flipped. Lay the same stencil again and every flipped bit flips back.
That is why **the same operation ciphers and deciphers**.

```
message  0100 1000   'H'
key      0011 1100
result   0111 0100   ← flipped where the key has a 1
key      0011 1100
back     0100 1000   'H' again
```

## How it works in my_pgp

1. Cut the message into pieces as long as the key (pad the last piece with zeros).
2. Flip each piece with the key (the subject also reverses the byte order of each piece).
3. Print the result in hex.

```
$ printf 'A' | ./my_pgp xor -c 00112233
00112272
```

## Is it secure?

- **In theory, perfectly**: with a truly random key as long as the message, used only once,
  this is the *one-time pad*, the only cipher proven unbreakable.
- **In practice, no**: here the key is short and reused for every piece. Patterns in the
  message show through, and the zero padding even prints parts of the key in clear.

## Going further

The [deep dive](../deep-dive/xor.md) covers the subject's byte order trick, block vs stream
mode, the Rust code and the tests.
