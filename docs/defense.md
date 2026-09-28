# Defense notes

The subject says that "a proper understanding of every cryptosystem implemented is mandatory",
and asks why the extra protections matter. For each system `my_pgp` implements, these notes
explain how it works and why it is secure or not, with the code that implements it.

Every example below was run on the real binary. Numbers are little-endian hexadecimal, as in
the subject: `19bb` is `0xbb19`.

## XOR

### How it works

`c = m ⊕ k`, byte by byte (`crates/xor`). XOR is its own inverse, so deciphering is the same
operation: `c ⊕ k = m ⊕ k ⊕ k = m`.

- Block mode (`-b`): the message and the key have the same length.
- Stream mode: the message is cut into key-sized blocks and the key repeats over them. The
  last block is padded with zeros, and deciphering strips trailing zeros.

### Why it is (in)secure

XOR is perfectly secure as a **one-time pad** (Shannon, 1949): if the key is truly random, as
long as the message and never reused, every plaintext of that length is equally likely given
the ciphertext. No amount of computing power helps. Every condition is needed, and `my_pgp`
breaks most of them:

- **Key reuse.** Two messages under the same key give `c1 ⊕ c2 = m1 ⊕ m2`: the key cancels
  out. Knowing or guessing one message gives the other:

  ```
  $ K=0badc0ffee0ddf000badc0ffee0ddf00
  $ echo 'attack at dawn!!' | ./my_pgp xor -c $K    # c1
  $ echo 'retreat at dusk!' | ./my_pgp xor -c $K    # c2
  ```

  XORing `c1`, `c2` and `attack at dawn!!` gives back `retreat at dusk!`. Without a known
  message, `m1 ⊕ m2` still falls to "crib dragging" with common words. This is how the
  Venona project read Soviet traffic whose pads had been reused.
- **Stream mode reuses the key inside one message.** A 16-byte key over a 1 KiB message is
  the Vigenère cipher: the key length shows in the repetitions (Kasiski, index of
  coincidence), then each key byte falls to frequency analysis.
- **Known plaintext gives the key**: `k = m ⊕ c`. Zero padding gives it away for free, since
  `0 ⊕ k = k`:

  ```
  $ printf 'A' | ./my_pgp xor -c 00112233
  41112233
  ```

- **Malleability.** Flipping bit `i` of `c` flips bit `i` of `m`. An attacker who knows the
  format can change `amount=100` into `amount=900` without knowing the key. Nothing detects
  it: there is no integrity check (see [Signatures](#signatures-bonus--s)).

XOR is only practical with a pad as long as all the traffic, which must be exchanged securely
beforehand. The subject says the same: "only if the key is as long as the message and is used
only once, which is not very practical".

## AES

### How it works

AES (FIPS 197) is a substitution-permutation network on a 128-bit block, viewed as a 4×4
matrix of bytes filled column by column (`crates/aes`). The key is 16, 24 or 32 bytes, for 10,
12 or 14 rounds.

- **Key expansion** (`key_expansion.rs`) derives one 16-byte round key per round, plus one,
  from the key: each new word is the previous one XORed with the word `Nk` positions back.
  Every `Nk` words, the word is first rotated (`RotWord`), passed through the S-box
  (`SubWord`) and XORed with a round constant (`Rcon`). AES-256 adds an extra `SubWord` in the
  middle of each group.
- **Cipher** (`rounds.rs`): `AddRoundKey`, then each round applies:
  - `SubBytes`: every byte goes through the S-box, the only non-linear step. The S-box is the
    inverse in GF(2^8) followed by an affine map. This implementation runs it as a logic
    circuit on all 16 bytes at once (`sbox.rs`, bitsliced) instead of reading a table (see
    [Timing attacks](#timing-attacks)).
  - `ShiftRows`: row `i` rotates left by `i` bytes, spreading each column over four columns.
  - `MixColumns`: each column is multiplied by a fixed matrix over GF(2^8), so each output
    byte depends on the four input bytes. With `ShiftRows`, every output bit depends on every
    input bit after two rounds.
  - `AddRoundKey`: XOR with the round key.

  The last round skips `MixColumns`. Deciphering applies the inverse steps in reverse order.
- The subject gives keys and ciphertexts as little-endian numbers. `reverse_words` reverses
  each 32-bit word to go between that order and the order of the state.
- Stream mode pads the message with zeros to a multiple of 16 bytes and ciphers each block
  independently: this is **ECB** mode.

The unit tests check the FIPS 197 key schedule (appendix A.1), the state after every round
in appendices B and C.1, the AES-192 and AES-256 vectors, and the NIST SP 800-38A ECB blocks.

### Why it is (in)secure

The block cipher itself is sound. After more than 20 years of analysis, the best attack on
full AES-128, the biclique attack (2011), costs about 2^126 operations: a factor 4 below brute
force, still far out of reach. Grover's algorithm on a quantum computer halves the key length
in bits; AES-256 keeps 128 bits of security against it.

The weaknesses are in how `my_pgp` uses it, as the subject asks:

- **ECB leaks patterns.** The same plaintext block under the same key always gives the same
  ciphertext block:

  ```
  $ printf 'YELLOW SUBMARINEYELLOW SUBMARINE' | ./my_pgp aes -c 57696e74657220697320636f6d696e67
  d10193ddbf7b4a29763d5fd21065fa7bd10193ddbf7b4a29763d5fd21065fa7b
  ```

  An image ciphered in ECB still shows its outline (the "ECB penguin"). Blocks can also be
  reordered, removed or copied between messages, and the result still deciphers.
- **Deterministic.** Ciphering the same message twice gives the same output, so an observer
  sees when a message repeats. Real modes add a random IV or nonce: CBC, CTR, GCM.
- **No integrity.** A modified ciphertext deciphers to garbage, with no error. Authenticated
  modes (GCM) or a MAC fix this. The X25519 mode of `my_pgp` uses AES-256-CTR with an
  HMAC-SHA256 tag for this reason (see [X25519](#x25519)).
- **Zero padding is ambiguous.** A message that ends with zero bytes loses them. PKCS#7
  padding, which always adds 1 to 16 bytes that give their own count, is unambiguous.

## RSA

### How it works

**Key generation** (`rsa -g P Q`, `crates/rsa`):

1. `n = p·q`.
2. `λ(n) = lcm(p−1, q−1)`, Carmichael's function.
3. `e` is the largest Fermat prime with `1 < e < λ(n)` and `gcd(e, λ(n)) = 1`.
4. `d = e⁻¹ mod λ(n)`, by the extended Euclidean algorithm.

The public key is `(e, n)` and the private key is `(d, n)`. With the subject's small example,
`p = 0xd3 = 211` and `q = 0xe3 = 227`:

- `n = 47897 = 0xbb19`, printed `19bb`.
- `λ(n) = lcm(210, 226) = 23730`.
- 65537 is larger than `λ(n)`, so `e = 257 = 0x0101`.
- `d = 257⁻¹ mod 23730 = 23453 = 0x5b9d`, printed `9d5b`.

**Ciphering**: the message bytes form a little-endian number `m < n`, and `c = m^e mod n`.
**Deciphering**: `m = c^d mod n`.

**Why deciphering gives `m` back.** `e·d ≡ 1 (mod λ(n))`, so `e·d = 1 + k·λ(n)`. Take `p`:

- If `p` does not divide `m`, Fermat's little theorem gives `m^(p−1) ≡ 1 (mod p)`. `p−1`
  divides `λ(n)`, so `m^(e·d) = m·(m^(p−1))^(k·λ(n)/(p−1)) ≡ m (mod p)`.
- If `p` divides `m`, both sides are `0 (mod p)`.

The same holds for `q`. Since `p ≠ q`, the Chinese remainder theorem gives
`m^(e·d) ≡ m (mod n)`.

**Modular exponentiation** (`crates/bigint`) uses Montgomery multiplication, which replaces
the division by `n` with shifts. The private exponent goes through a constant-time fixed-window
algorithm; the public exponent through a faster sliding window (see
[Timing attacks](#timing-attacks)).

### λ(n) rather than φ(n)

The proof above only needs `p−1` and `q−1` to divide `e·d − 1`. `λ(n) = lcm(p−1, q−1)` is the
smallest number they both divide: it is the exponent of the group of units mod `n`, the
smallest `t` with `m^t ≡ 1 (mod n)` for every `m` coprime with `n`.

Euler's `φ(n) = (p−1)(q−1) = λ(n)·gcd(p−1, q−1)` also works, since it is a multiple of `λ(n)`.
But `p−1` and `q−1` are both even, so `λ(n) ≤ φ(n)/2`. Computing `d` modulo `λ(n)` gives the
smallest valid private exponent, so deciphering does fewer squarings. FIPS 186-4 also computes
`d` modulo `λ(n)`. Security is the same either way: knowing any valid `d` lets you factor `n`.

### Choice of e

The Fermat primes are `F_k = 2^(2^k) + 1`: 3, 5, 17, 257, 65537, the only ones known.

- **Fast.** In binary, `F_k` is a 1, zeros, and a 1. `m^65537` costs 16 squarings and a single
  multiplication.
- **Easy to make coprime.** `e` is prime, so `gcd(e, λ(n)) = 1` unless `e` divides `λ(n)`.
- **The largest is the safest.** Small exponents like 3 make the textbook attacks below
  practical. FIPS 186-4 requires `e > 2^16`, so 65537 is the smallest value it allows, and
  almost every real RSA key uses it.
- `e < λ(n)`: an exponent can be reduced modulo `λ(n)`, so a larger `e` is just a smaller one
  in disguise. That is why the small subject key falls back to 257.

A small `e` does not weaken the private key. A small `d` would: Wiener's attack recovers
`d < n^0.25/3` from `(e, n)` with continued fractions. With `e = 65537`, `d` is about as large
as `λ(n)`.

### Random primes (bonus, `rsa --bits N`)

`prime::gen_prime` draws random `N/2`-bit odd numbers from `/dev/urandom`, with the top two
bits set so that `p·q` has exactly `N` bits. A candidate goes through trial division by the
primes below 2000, then 40 rounds of Miller-Rabin with random bases. A composite passes with
probability at most `4^−40 = 2^−80`.

Miller-Rabin and not Fermat's test: Carmichael numbers such as `561 = 3·11·17` satisfy
`a^(n−1) ≡ 1 (mod n)` for every base coprime with them, so Fermat's test cannot reject them.
Miller-Rabin also checks that the square roots of 1 it meets are ±1. The unit tests include
Carmichael numbers.

The randomness matters as much as the primality. In 2012, Heninger et al. factored about 0.5%
of the TLS keys on the Internet by computing the `gcd` of every pair of moduli: devices with
little entropy at boot had generated keys sharing a prime. The 2008 Debian OpenSSL bug left
only 32 767 possible keys per key size.

### Why it is (in)secure

RSA is as strong as factoring `n` is hard, and it is only safe with a large key and a padding
scheme.

**Key size.** The subject's small key (`n = 0xbb19`) factors instantly by trial division. Its
large key has a 512-bit `n`: RSA-155, a 512-bit modulus, was factored in 1999, and today the
same takes a few hours of rented cloud computing (Valenta et al., 2015). NIST SP 800-57 asks
for at least 2048 bits, and 3072 bits for 128-bit security: `rsa --bits 2048`.

**Textbook RSA**, as the subject asks for, is broken even with a large key:

- **Deterministic.** The same message always gives the same ciphertext
  (`echo WF | ./my_pgp rsa -c 0101-19bb` prints `8f84` every time). Anyone can cipher guesses
  with the public key and compare. A "yes"/"no" answer is read at once.
- **Malleable.** `(m^e)·(r^e) = (m·r)^e`: multiplying `c` by `r^e` multiplies the hidden `m`
  by `r`. With the small key, `8f84·2^257 mod n = e890`, which deciphers to
  `0x8cae = 2·0x4657` ("WF"). If the victim deciphers chosen ciphertexts, this recovers any
  `m`: ask for `c·r^e`, divide the answer by `r`.
- **Small message, small `e`.** If `m^e < n`, the modulus never applies and `m` is the plain
  `e`-th root of `c`. With `e = 3` and a 2048-bit `n`, any message below 682 bits falls.
- **Håstad's broadcast attack.** The same `m` sent with `e = 3` to three recipients gives
  `m^3` modulo three coprime moduli. The Chinese remainder theorem rebuilds `m^3` over the
  integers, and a cube root gives `m`.
- **Common modulus.** Two keys sharing `n` with coprime `e1`, `e2` reveal any message ciphered
  under both, through Bézout's identity. `my_pgp` never shares `n`.

[RSA-OAEP](#rsa-oaep-bonus--p) fixes all of these except key size. Deciphering does not use
the Chinese remainder theorem, so the Bellcore fault attack (one faulty CRT half reveals `p`)
does not apply.

## PGP (`pgp-xor`, `pgp-aes`)

### How it works

1. Cipher the message with a symmetric key `K`: XOR or AES (`crates/pgp`).
2. Cipher `K` with the recipient's RSA public key.
3. Print the ciphered key, then the ciphered message.

The recipient deciphers the first line with the RSA private key to get `K`, then the message
with `K`.

**Why combine them.** Symmetric ciphers are fast and take messages of any length, but both
sides must already share the key: `n` people need `n(n−1)/2` keys, each exchanged securely.
RSA needs no shared secret, but it is slow (a few hundred 2048-bit decryptions per second,
`cargo run --release --bin bench`) and ciphers at most one number below `n` per operation.
The hybrid uses RSA once, on a short key, and the symmetric cipher for the data. OpenPGP,
S/MIME and TLS 1.2's RSA key exchange all work this way. The modern name is KEM/DEM: a key
encapsulation mechanism and a data encapsulation mechanism.

### Why it is (in)secure

The hybrid is only as strong as its weakest part, and here each part keeps its weaknesses:

- **The symmetric key is not random.** The subject passes it on the command line for
  debugging. Real PGP draws a fresh session key for every message. Here, the key ends up in
  the shell history and in `ps`, and nothing stops reusing it. With `pgp-xor`, reuse is the
  two-time pad from [XOR](#xor).
- **Textbook RSA shows the reuse.** The first line is deterministic, so two messages under
  the same key start with the same line (`$PUBLIC` is the subject's public key, as in the
  README):

  ```
  $ echo one | ./my_pgp pgp-aes -c "57696e74657220697320636f6d696e67:$PUBLIC" | head -1
  97f2af4c1b712008c1e46935...
  $ echo two | ./my_pgp pgp-aes -c "57696e74657220697320636f6d696e67:$PUBLIC" | head -1
  97f2af4c1b712008c1e46935...
  ```

- `pgp-xor` inherits the repeating key, and `pgp-aes` inherits ECB.
- **No integrity**: both lines can be modified without detection.
- **The subject's 512-bit RSA key** can be factored, which reveals `K` and then everything.

The bonuses close most of these gaps: `-p` randomizes the ciphered key (OAEP), `-s` signs both
lines, and `rsa --bits 2048` gives a key that cannot be factored. Real OpenPGP (RFC 9580) also
uses an authenticated mode (AEAD) for the data.

## X25519

### How it works

X25519 (RFC 7748) is Diffie-Hellman on Curve25519, the Montgomery curve
`y² = x³ + 486662·x² + x` over the field of integers modulo `p = 2^255 − 19`
(`crates/x25519`).

- **Field** (`field.rs`): an element is 5 limbs of 51 bits. Since `2^255 ≡ 19 (mod p)`, the
  part of a product above bit 255 is folded back with a multiplication by 19, with no
  division. Inversion is `x^(p−2)` (Fermat's little theorem).
- **Scalar multiplication** (`ladder.rs`): `X25519(k, u)` computes the `x`-coordinate of
  `k·P`, where `u` is the `x`-coordinate of `P`, with the Montgomery ladder. It keeps two
  points whose difference is always `P`, and for each of the 255 bits of `k` does one
  addition and one doubling, swapping the two points depending on the bit. Points are in
  projective `(X : Z)` form to avoid an inversion at each step; one inversion at the end
  gives `x = X/Z`.
- **Clamping**: before use, the scalar has its 3 low bits cleared (a multiple of the
  cofactor 8, so points of small order vanish), bit 255 cleared and bit 254 set (so every
  scalar has the same length and the ladder always runs the same number of steps).
- **Keys** (`ed25519.rs`): like the subject's example, keys are an Ed25519 pair (RFC 8032).
  The private key is a random 32-byte seed; its scalar is the first half of SHA-512(seed),
  clamped. The public key is that scalar times the base point of the twisted Edwards curve
  `-x² + y² = 1 + d·x²·y²`, encoded as `y` with the sign of `x`. Both curves are the same
  group in different coordinates, so the X25519 public key is `u = (1 + y) / (1 - y)`, and
  `X25519(scalar, 9)` gives the same `u` (9 is the Montgomery `u` of the base point).
- **Shared secret**: `X25519(a, B) = X25519(b, A)`, since `a·(b·G) = b·(a·G)`.

`my_pgp X25519 -c` turns this key exchange into encryption, like ECIES:

1. Generate an ephemeral key pair `(e, E)` and a random 16-byte nonce.
2. `s = X25519(e, recipient public key)`. An all-zero `s`, which a public key of small order
   produces, is rejected.
3. HKDF-SHA256 (RFC 5869), with `E` as salt and `my_pgp X25519 AES-256-CTR` as info, derives
   two 32-byte keys from `s`: one for AES, one for HMAC.
4. Cipher the message with AES-256 in CTR mode: the nonce, incremented for each block, is
   ciphered to make a keystream, which is XORed with the message. No padding is needed, so
   any binary message comes back exactly.
5. Output `E || nonce || ciphertext || tag`, where the tag is HMAC-SHA256 over everything
   before it.

Deciphering recomputes `s` from the private key and `E`, checks the tag in constant time, and
only then deciphers.

### Why it is (in)secure

- **Hard problem.** Recovering a private key means solving the discrete logarithm on the
  curve. The best known attack, Pollard's rho, costs about 2^126 operations: 128-bit security
  with 32-byte keys, where RSA needs 3072 bits.
- **Designed to be implemented safely.** The ladder does the same operations for every bit,
  and the swap is an XOR under a mask, so it runs in constant time. Every 32-byte string is a
  valid public key, and the curve's twist is also secure, so invalid-curve attacks do not
  apply and no point validation is needed.
- **Randomized.** A new ephemeral key and nonce for every message: the same message never
  gives the same ciphertext, and the AES key is never reused.
- **Authenticated.** The HMAC is computed over the ciphertext (encrypt-then-MAC) and checked
  before anything is deciphered, so a modified ciphertext or a wrong key exits 84. This is
  what the ECB and XOR modes lack.

Limits:

- **No sender authentication.** Anyone with the recipient's public key can cipher a message.
  `-s` adds an RSA signature.
- **No forward secrecy against the recipient.** The ephemeral key protects nothing if the
  recipient's private key leaks later: every past message can be deciphered.
- The private key is passed on the command line.
- A quantum computer running Shor's algorithm would break X25519 and RSA alike.

## RSA-OAEP (bonus, `-p`)

### How it works

OAEP (RFC 8017 §7.1, `crates/padding`) turns a message `M` into a block `EM` as large as the
modulus (`k` bytes) before RSA:

```
DB         = lHash || 00 00 .. 00 || 01 || M     lHash = SHA-256 of the empty label
seed       = 32 random bytes
maskedDB   = DB   ⊕ MGF1(seed, k − 33)
maskedSeed = seed ⊕ MGF1(maskedDB, 32)
EM         = 00 || maskedSeed || maskedDB
```

MGF1 stretches its input into a mask by hashing it with a counter:
`SHA-256(input || 0) || SHA-256(input || 1) || ...`. The two masks form a two-round Feistel
network: every bit of `EM` depends on the whole seed and the whole message.

Decoding undoes the masks, then checks the leading `00`, `lHash` and the `01` separator. Any
failure gives the same error.

The message can be at most `k − 66` bytes, and the modulus at least 66 bytes: the subject's
512-bit (64-byte) keys are too small.

### Why it is (in)secure

- **Randomized**: the random seed makes the same message cipher differently each time, which
  stops dictionary attacks.
- **Full size**: `EM` is as large as `n`, so the `e`-th root and Håstad attacks fail.
- **Not malleable**: multiplying the ciphertext scrambles `EM`, and the checks reject it.

OAEP is proven secure against chosen-ciphertext attacks (IND-CCA2), in the random oracle
model (Fujisaki, Okamoto, Pointcheval and Stern, 2001).

Its predecessor, PKCS#1 v1.5 encryption, pads with `00 02 || random non-zero bytes || 00 || M`.
Bleichenbacher (1998) showed that a server revealing whether a ciphertext has valid padding
lets an attacker decipher any message with about a million queries. The same attack still
worked against major TLS servers in 2017 (ROBOT). OAEP has a similar risk if the error shows
which check failed (Manger, 2001), which is why `decode` runs every check, scans for the
separator without branching, and returns one error.

## Signatures (bonus, `-s`)

### How it works

RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §8.2, `crates/sign`):

```
EM = 00 01 || FF FF .. FF || 00 || DigestInfo(SHA-256) || SHA-256(message)
signature = EM^d mod n        (signer's private key)
```

Verifying computes `signature^e mod n` with the signer's public key, rebuilds the expected
`EM` from the message, and compares the two.

`my_pgp` signs the ciphered output as printed, both lines for `pgp-*`, and appends the
signature as a last line. Deciphering checks it before deciphering anything. The signing key
pair is separate from the cipher key.

SHA-256 (FIPS 180-4, `crates/hash`) compresses 64-byte blocks through 64 rounds into a 256-bit
digest. Finding a collision costs about 2^128 operations.

### Why it is (in)secure

- **Integrity and origin.** XOR, AES in ECB and textbook RSA let anyone modify a ciphertext
  without detection. A valid signature proves that the holder of the private key produced
  these exact bytes. In `pgp-*`, it also covers the ciphered key, so swapping in another key
  is detected.
- **Why hash, why pad.** Textbook RSA signatures are forgeable: `s^e mod n` is a valid
  signature of whatever it gives for any random `s`, and `sig(m1)·sig(m2) = sig(m1·m2)`.
  Hashing fixes the input size and destroys that algebra; the `00 01 FF..FF 00` structure
  leaves no room for a forger to adjust.
- **Compare, don't parse.** In 2006, Bleichenbacher forged signatures for `e = 3` against
  verifiers that parsed `EM` and ignored trailing bytes. `my_pgp` rebuilds the whole expected
  `EM` and compares it byte for byte, so there is nothing to parse.
- **Separate keys.** Signing with `d` is the same operation as deciphering with `d`. Using one
  key pair for both would let a signing request decipher a message.
- **Sign the ciphertext.** Checking before deciphering means a forged message never reaches
  the decipher step, which could otherwise serve as an oracle.

Limits:

- The signature shows who produced the ciphertext, not who wrote the plaintext. An attacker
  can strip it and sign with their own key: the recipient must check that the verifying key
  belongs to the expected sender.
- PKCS#1 v1.5 signatures are deterministic and have no security proof. RSASSA-PSS has one and
  is the recommended choice for new designs.
- The modulus must be at least 62 bytes.

## Timing attacks

### How they work

If the time an operation takes depends on a secret, an attacker who can time it (another
process on the machine, or a server over the network) repeats the measurement until the
difference stands out from the noise:

- **RSA** (Kocher, 1996): square-and-multiply does an extra multiplication for each 1 bit of
  `d`, so the total time depends on `d`. Brumley and Boneh (2003) recovered a key from an
  OpenSSL server over a local network.
- **AES** (Bernstein, 2005): table-based implementations read a table at an index that
  depends on `key ⊕ plaintext`, and cache timing reveals the index.
- **Comparisons**: `==` on byte slices stops at the first difference, so a MAC tag can be
  guessed one byte at a time.

### What `my_pgp` does

The secret-dependent code avoids branches and memory accesses indexed by secrets:

- RSA with the private exponent uses fixed-window exponentiation, and reads every table entry
  under a mask. The Montgomery final subtraction is masked instead of branched. The public
  exponent keeps a faster variable-time path, since it is public.
- AES has no tables: the S-box is a circuit of AND, XOR and NOT gates applied to the whole
  state, and the key schedule's GF(2^8) arithmetic always runs the same steps.
- X25519 swaps points with masks, and serializes field elements without branching.
- OAEP decoding and the HMAC tag check scan every byte.

`cargo run --release --bin timing` measures each primitive with a fixed secret against random
secrets and runs Welch's t-test. Every primitive leaked before these fixes; none does after.
Rust gives no constant-time guarantee: LLVM once turned a mask back into a branch, which only
the measurement caught. [constant-time-audit.md](constant-time-audit.md) has the details, the
measurements and the leaks that remain.

## Why the extra protections matter

| Protection | Attack it stops |
|---|---|
| OAEP (`-p`) | Dictionary attacks on deterministic RSA, malleability, `e`-th root and Håstad attacks, padding oracles |
| Signatures (`-s`) | Undetected tampering (bit flipping, ECB block reordering, ciphered key substitution), impersonation of the sender |
| Random primes (`--bits`) | Keys too small to resist factoring; primes chosen by hand or with weak randomness |
| Authenticated encryption (X25519 mode) | ECB patterns, key reuse, malleability of the ciphertext |
| Constant-time code | Recovering `d`, AES keys or X25519 scalars by timing |

Each basic algorithm does one job: XOR and AES hide data, RSA and X25519 share a key. None of
them alone stops an attacker from changing a message, replaying it or learning that two
messages are equal. That is why the subject asks for more than the basic algorithms.

## References

- C. Shannon, *Communication Theory of Secrecy Systems*, 1949.
- FIPS 197, *Advanced Encryption Standard*; NIST SP 800-38A, *Block Cipher Modes of
  Operation*.
- RFC 8017, *PKCS #1: RSA Cryptography Specifications Version 2.2* (OAEP, PKCS#1 v1.5
  signatures).
- FIPS 186-4, *Digital Signature Standard* (RSA key generation, `e > 2^16`).
- D. Boneh, *Twenty Years of Attacks on the RSA Cryptosystem*, 1999.
- RFC 7748, *Elliptic Curves for Security* (X25519); RFC 5869, *HKDF*; RFC 2104, *HMAC*;
  FIPS 180-4, *Secure Hash Standard*.
- D. Bleichenbacher, *Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption
  Standard PKCS #1*, 1998; J. Manger, *A Chosen Ciphertext Attack on RSA OAEP*, 2001.
- N. Heninger et al., *Mining Your Ps and Qs*, 2012.
- P. Kocher, *Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other
  Systems*, 1996.
- RFC 9580, *OpenPGP*.
