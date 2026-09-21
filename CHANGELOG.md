## 0.2.0

* `CryptoV2`: envelope v2 (X25519 + HKDF-SHA256 + AES-256-GCM, Ed25519
  signature) with `generateX25519KeyPair`, `generateEd25519KeyPair`,
  `signEd25519`/`verifyEd25519`, `encryptEnvelope`/`decryptEnvelope`,
  `encryptPayload`/`decryptResponse`. Built on the `cryptography` package;
  add `cryptography_flutter` in apps for native speed.
* `Crypto.encryptEnvelopeWithKeys` / `decryptEnvelopeWithKeys` and
  `Crypto.signBytes` — reuse parsed keys (~25% faster envelopes).
* Benchmark rows for cached keys and v2.

## 0.1.0

Interoperability release — the wire format is now shared and cross-tested with
the Go `crypto_utils` package and the `crypto_utils` Rust crate.

### Breaking

* `encryptWithPublicKey` / `encryptWithUint8ListPublicKey` now encrypt the
  message bytes directly with PKCS#1 v1.5. Previously the `encrypt` package
  silently base64-encoded the message first, so the RSA plaintext was the
  base64 *text* of the AES key. Servers running the updated Go package accept
  both forms; the two RSA tests that failed because of this now pass.
* `decryptWithPrivateKey` returns the unpadded plaintext (padding was left in
  place before and stripped ad hoc by callers).
* `decryptWithAES` decodes the plaintext as UTF-8 instead of Latin-1.
* `decryptResponse` no longer brute-forces key windows; it accepts the raw
  32-byte key (canonical) and the legacy 44-character base64 key.
* Removed the `encrypt` and `logger` dependencies. Diagnostic output is off by
  default; set `Crypto.logger` to enable it.

### Performance

* AES-GCM now uses a table-based GHASH (`AesGcm`) instead of PointyCastle's
  bit-by-bit multiply: 1 MiB in ~90 ms instead of ~1.3 s. Verified against
  NIST SP 800-38D vectors, PointyCastle's own GCM and the Go/Rust suites.
* Dependencies bumped to `pointycastle 4.0.0`, `flutter_lints 6`.

### Added

* `Crypto.generateRSAKeyPair()` — PKCS#1/PKIX PEM keys as base64 strings.
* `encryptWithPublicKeyOAEP` / `decryptWithPrivateKeyOAEP` (OAEP-SHA256).
* `encryptEnvelope` / `decryptEnvelope` with optional signing/verification and
  OAEP; `encryptPayload` gained `senderPrivateKey`, `decryptResponse` gained
  `senderPublicKey`.
* `encryptWithAESBytes` / `decryptWithAESBytes`, `sign` / `verify` (base64).
* `RsaKeyCodec` — PEM/DER encoding and decoding of RSA keys; `AesGcm` — fast AES-GCM.
* `benchmark/bench.dart` micro-benchmarks.
* `tool/interop.dart` CLI used by the cross-language suite.

## 0.0.2

* RSA/AES helpers with PKCS#1 padding, payload encryption, response decryption.

## 0.0.1

* Initial release.
