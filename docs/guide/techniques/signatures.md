# RSA signatures (bonus: `-s`)

[← Guide index](../README.md) · Math and code: [deep dive](../deep-dive/signatures.md) · Crate: [sign](../crates/sign.md) · Security: [defense.md § Signatures](../../defense.md#signatures-bonus--s)

## In one sentence

RSA backwards: lock a fingerprint of the message with your **private** key, and anyone can
check it with your **public** key, proving you sent it and nobody changed it.

## The picture

Ciphering hides a message, but doesn't prove who sent it. A signature is a wax seal:

1. **Sign**: hash the message (SHA-256), put the hash in a fixed frame, raise it to your
   private exponent `d`. That's the signature.
2. **Verify**: raise the signature to the public exponent `e`, and compare with the frame
   rebuilt from the message. Equal: authentic. Different: forged or modified.

Why hash and frame instead of signing the raw message? Raw RSA signatures can be forged by
working backwards from a random value. The frame (`00 01 FF FF … 00 + "SHA-256" + hash`) is a
pattern a forger can't hit.

## How it works in my_pgp

`-s` takes an extra key, separate from the cipher key:

- **Cipher** (`-c … -s <private d-n>`): cipher as usual, then add the signature of the
  ciphered output as a last line.
- **Decipher** (`-d … -s <public e-n>`): check the signature first; if it's wrong, stop with
  exit 84 without deciphering anything.

## Is it secure?

Yes: RSASSA-PKCS1-v1_5 with SHA-256 is the scheme behind most HTTPS certificates. The verifier
rebuilds and compares the whole frame instead of parsing it, which avoids a known forgery
(Bleichenbacher 2006).

## Going further

The [deep dive](../deep-dive/signatures.md) shows the exact frame, why raw signatures are
forgeable, and the code.
