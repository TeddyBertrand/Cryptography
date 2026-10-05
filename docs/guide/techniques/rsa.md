# RSA

[← Guide index](../README.md) · Math and code: [deep dive](../deep-dive/rsa.md) · Crate: [rsa](../crates/rsa.md) · Security: [defense.md § RSA](../../defense.md#rsa)

## In one sentence

A padlock anyone can close (public key) but only you can open (private key), built on the
fact that multiplying two big primes is easy but splitting the result back is not.

## The picture

You hand out open padlocks to everyone. Anyone can put a message in a box and click the lock
shut. Only you have the key that opens it.

The math behind the padlock:

- Take two secret primes `p` and `q`, multiply them: `n = p × q`. Publishing `n` is safe:
  nobody can find `p` and `q` back from a 2048-bit `n` (it would take longer than the age of
  the universe).
- From `p` and `q` you compute a pair of exponents `e` (public) and `d` (private) that
  **cancel each other out**: raising to `e` then to `d` gives the original number back
  (everything "mod n", i.e. wrapping around at `n` like a clock).
- Computing `d` from `e` needs `p` and `q`. Without them, you're stuck.

```
cipher:    c = m^e mod n        anyone, with the public key (e, n)
decipher:  m = c^d mod n        only the owner, with the private key (d, n)
```

## How it works in my_pgp

```
$ ./my_pgp rsa -g d3 e3                  # build keys from the primes 0xd3 and 0xe3
public key: 0101-19bb
private key: 9d5b-19bb
$ echo WF | ./my_pgp rsa -c 0101-19bb
8f84
$ echo 8f84 | ./my_pgp rsa -d 9d5b-19bb
WF
```

Bonus: `rsa --bits 2048` draws real random primes instead (see [primes](primes.md)).

## Is it secure?

- **The idea: yes**, with big enough keys (2048 bits or more). The subject's keys are toy-size.
- **"Textbook" RSA, as the subject asks: no.** The same message always gives the same
  ciphertext, and an attacker can tamper with it in predictable ways. Real systems add random
  padding first: that is our [OAEP bonus](oaep.md) (`-p`).
- **Slow and size-limited**: RSA only ciphers one number smaller than `n`. That's why it is
  used to carry a symmetric key ([PGP hybrid](pgp-hybrid.md)), not whole messages.

## Going further

The [deep dive](../deep-dive/rsa.md) has the key-generation formulas with the subject's worked
example, the proof that deciphering works (Fermat, Chinese remainder theorem), why λ(n) instead
of φ(n), and why `e = 65537`.
