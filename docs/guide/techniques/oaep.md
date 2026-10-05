# RSA-OAEP padding (bonus: `-p`)

[← Guide index](../README.md) · Math and code: [deep dive](../deep-dive/oaep.md) · Crate: [padding](../crates/padding.md) · Security: [defense.md § RSA-OAEP](../../defense.md#rsa-oaep-bonus--p)

## In one sentence

Before RSA, wrap the message with random bytes and scramble it, so the same message never
ciphers the same way twice and any tampering is detected.

## The problem it fixes

Textbook RSA (what the subject asks) has three flaws:

- **Same message, same ciphertext**: an attacker can cipher guesses ("yes", "no") with your
  public key and compare.
- **Tamperable**: multiplying the ciphertext by a chosen value multiplies the hidden message
  in a predictable way.
- **Small messages** can sometimes be recovered with a plain root.

## The picture

Put the message in an envelope with a fresh random seed, then shake it so that every byte of
the envelope depends on the seed and the message:

```
[ check value | zeros | 01 | message ]   ← the message, with a known structure
          + 32 random bytes                ← new for every encryption
          → mixed together with SHA-256
          → RSA
```

Deciphering undoes the mixing and checks the structure. If anything was changed, the structure
is broken and the message is refused. All failures give **the same error at the same speed**,
otherwise the error itself leaks information (Manger's attack).

## How it works in my_pgp

```
$ ./my_pgp rsa --bits 1024           # OAEP needs a modulus of at least 66 bytes
$ echo hello | ./my_pgp rsa -c -p <public key>
```

Run the second line twice: different output each time, both decipher to `hello`.
The subject's 512-bit keys are too small for OAEP.

## Is it secure?

Yes: RSA-OAEP (RFC 8017) is the standard way to encrypt with RSA. Our implementation is
checked against OpenSSL and deciphers OpenSSL's ciphertexts.

## Going further

The [deep dive](../deep-dive/oaep.md) has the exact block layout, MGF1, the size limit and the
branch-free padding check.
