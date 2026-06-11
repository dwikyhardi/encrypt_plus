# 5.0.5

- Packaging: renamed the package to `encryptor_plus` (import as `package:encryptor_plus/encrypt.dart`).
- Security: `Key.stretch` now uses PBKDF2-HMAC-SHA256 with a default of 600000 iterations (was HMAC-SHA1 with 100). Password-derived keys are dramatically harder to brute-force; pass `iterationCount` to tune.
- Security: `RSA` now defaults to OAEP padding with a SHA-256 digest instead of PKCS#1 v1.5. PKCS#1 v1.5 is vulnerable to Bleichenbacher padding-oracle attacks and remains available via `RSAEncoding.PKCS1` for backwards compatibility.
- Security: `Encrypter.decrypt`/`decrypt16`/`decrypt64` no longer decode with `allowMalformed: true` by default, so corrupted/tampered ciphertext in unauthenticated modes surfaces a `FormatException`. Opt back in with `allowMalformed: true`.
- Robustness: `decodeHexString` now throws a `FormatException` for odd-length input instead of relying on an `assert` (which is stripped in release builds).
- Docs: documented that Salsa20 is unauthenticated, clarified the Fernet `IV` behavior, and fixed several typos.
- Security: use a constant-time HMAC comparison when verifying Fernet tokens to prevent timing attacks (CWE-208).
- Security: AES-GCM now always runs through the authenticated cipher (even with `padding: null`), so the authentication tag is appended on encryption and verified on decryption. Tampered ciphertexts are now correctly rejected.
- Security: `RSASigner` now delegates PKCS#1 v1.5 padding and ASN.1 `DigestInfo` encoding/verification to PointyCastle's well-tested signer instead of a hand-rolled implementation, and SHA-512 signatures are now supported.
- Docs: documented that non-GCM AES modes are unauthenticated and recommended AES-GCM (or Fernet) for tamper resistance.

# 5.0.4

- Force Pointycastle version

# 5.0.3

- Fixed tests failing with AES ECB with padding by @JimWuerch in #312
- fix: Could not parse version "~3.6.2" by @Marc-R2 in #315

# 5.0.2

- Update pointycastle version to support AES-GCM with Flutter Web
- Support AES-GCM
- Fixed null safety related warnings from `package:asnlib`.

# 5.0.1

- Fix web support

# 5.0.0

- Null safety support stable (sdk: ">=2.12.0 <3.0.0")

# 5.0.0-beta.1

- Preview/prerelase null safety support

# 4.1.0

- PointyCastle v2

# 4.0.3

- Fix UTF-8 conversion on Fernet keys.

# 4.0.2

- Fix streamble AES modes without padding.

# 4.0.1

- Upgrade dependencies.

# 4.0.0

- Digital signatures signing and verification.

# 3.3.1

- Move I/O helper to another lib

# 3.3.0

- Added the Fernet algorithm, thanks to [@timfeirg](https://github.com/timfeirg)
- Moved the secure random logic to the lib
- Added key stretching

# 3.2.0

- Fix wrong casting.
- Add decryptBytes, avoids UTF-8 high coupling.
- Add public decryption and private encryption for digital signature verification.

# 3.1.0

- Add support for CRLF PEM keys.
- Fix AES without padding.
- Add `encryptBytes` method.

# 3.0.0

- Enforce IV uniqueness.

# 2.2.0

- AES padding is now optional with defaults to PKCS7.

# 2.1.0

- `secure-random` command-line tool.

# 2.0.0

- All new API

# 1.0.1

- RSA

# 1.0.0

- Stable and documented API

# 0.2.0+2

- Remove unnecessary `new`s
- Improve static typing
- Add examples index (README)

# 0.2.0+1

- Refresh dependencies, make sure it works on Dart 2
