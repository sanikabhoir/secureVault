# SecureVault — Layered Encryption System (Java)

A file/text encryption CLI written in pure Java (no external dependencies —
just the JDK's built-in `javax.crypto` / `java.security`), combining several
layers of cryptographic engineering:

- **AES-256-GCM** — authenticated symmetric encryption (confidentiality + integrity in one step)
- **PBKDF2-HMAC-SHA256** (200,000 iterations) — turns a password into a strong key, with a random salt per file
- **RSA-2048 hybrid mode** — public-key encryption of a random session key (like TLS/PGP do it)
- **RSA digital signatures (SHA256withRSA)** — proves who encrypted a file and that it wasn't altered
- **Custom keyed permutation layer** — an extra defense-in-depth byte-shuffling step applied before AES (see the honesty note in `PermutationLayer.java` — it's not a substitute for AES, it's an additional layer)
- **Built-in tamper detection** — flipping even one bit in an encrypted file causes decryption to fail loudly instead of silently returning garbage

## Requirements

- JDK 17 or newer (tested on OpenJDK 21). No Maven, no internet access needed — it's plain `javac`/`java`.

Check your version:
```
java -version
javac -version
```

## How to run it

1. Unzip the project and open a terminal in the `SecureVault` folder.

2. Compile:
```
javac -d bin src/com/securevault/*.java src/com/securevault/crypto/*.java src/com/securevault/util/*.java
```

3. Run from the `bin` folder (or add `-cp bin` from the project root):
```
cd bin
java com.securevault.Main <command> ...
```

### Quickest way to see it work: the built-in self-test

```
java com.securevault.Main demo
```

This automatically: encrypts and decrypts a sample file with a password,
confirms a wrong password is rejected, does a full RSA key-generation +
hybrid encrypt/decrypt round trip, flips a bit in an encrypted file to prove
tamper detection works, and signs + verifies a file. Everything happens in
the `bin` folder so you can inspect the generated files afterward.

### Commands

**Password-based encryption** (simplest mode — good for personal files):
```
java com.securevault.Main encrypt  secret.txt secret.vault "my strong password"
java com.securevault.Main decrypt  secret.vault recovered.txt "my strong password"
```

**RSA hybrid mode** (encrypt to someone else's public key, like email encryption):
```
java com.securevault.Main genkeys      alice_private.key alice_public.key
java com.securevault.Main encrypt-rsa  secret.txt secret.vault alice_public.key
java com.securevault.Main decrypt-rsa  secret.vault recovered.txt alice_private.key
```

**Digital signatures** (prove authorship / detect tampering):
```
java com.securevault.Main sign    document.txt document.sig alice_private.key
java com.securevault.Main verify  document.txt document.sig alice_public.key
```

## Project structure

```
SecureVault/
├── README.md
└── src/com/securevault/
    ├── Main.java                  CLI entry point + file container format + self-test
    ├── crypto/
    │   ├── AESCipherUtil.java     AES-256-GCM encrypt/decrypt
    │   ├── KeyDerivation.java     PBKDF2 password -> key
    │   ├── PermutationLayer.java  keyed byte-permutation (defense-in-depth layer)
    │   └── RSAUtil.java           RSA keygen, key wrapping, sign/verify
    └── util/
        └── FileUtil.java          small file I/O helpers
```

## Design notes (good talking points for an interview)

- **Why GCM over CBC?** GCM is an AEAD (authenticated encryption with
  associated data) mode — it gives you a forgery-proof auth tag for free,
  so you don't need a separate HMAC pass and can't forget to check it.
- **Why 200,000 PBKDF2 iterations?** It's a deliberate slowdown to make
  brute-forcing weak passwords expensive. This is a tunable — increase it
  as hardware gets faster.
- **Why is the permutation layer honest about not adding "real" security?**
  Because claiming a novel scheme is unbreakable is exactly the mistake
  real cryptographers watch for. The layer is documented for what it
  actually does: a keyed, reversible transform for defense-in-depth, not
  a proof of extra entropy.
- **What this project deliberately does NOT claim:** that it invented an
  unbreakable algorithm. It demonstrates correct use of well-vetted
  primitives (AES-GCM, RSA-OAEP, PBKDF2, RSA signatures) plus one clearly
  labeled experimental layer — which is what real-world crypto engineering
  looks like.

## Ideas for extending it further

- Swap the permutation layer's PRNG for a cryptographically secure DRBG
- Add ChaCha20-Poly1305 as an alternate cipher option
- Add a simple JavaFX GUI on top of the same `crypto` package
- Add streaming encryption for large files instead of loading them fully into memory
