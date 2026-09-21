# flutter_crypto_security

Encrypt, sign and exchange data between a Flutter app and a Go or Rust
backend — with one wire format that all three understand.

This package is the **app-side** half of the toolkit:

| Implementation | Repository |
|---|---|
| Dart / Flutter (this package) | `flutter_crypto_security` |
| Go | [`crypto_utils`](https://github.com/sudhi001/crypto_utils) |
| Rust | `crypto_utils_rust` |

All three are cross-tested against each other (216 checks in `interop/run.sh`)
and against a real envelope captured from production.

## What it does, in plain English

Think of sending a valuable letter:

1. The letter goes in a **steel box locked with a fresh padlock key** — that is
   AES-256-GCM, fast and tamper-evident.
2. The padlock key is far too sensitive to mail in the open, so it is snapped
   into a **tiny box that only the server can open** — RSA with the server's
   public key.
3. Optionally you press your **wax seal** on the parcel so the server knows it
   really came from this device — an RSA signature.
4. Everything ships as one small JSON **envelope**:

```json
{ "payload": "…locked box…", "key": "…tiny box…", "nonce": "…fresh-start number…", "signature": "…wax seal…" }
```

`Crypto.encryptPayload` builds that parcel for the server; `Crypto.decryptResponse`
opens the server's reply. Everything else in the package is the individual
tools those two use. A longer explanation with a glossary lives in
`interop/PLAIN_ENGLISH.md`.

## Installation

```yaml
dependencies:
  flutter_crypto_security:
    git:
      url: https://github.com/sudhi001/flutter_crypto_security.git
```

```dart
import 'package:flutter_crypto_security/flutter_crypto_security.dart';
```

Pure Dart (only `pointycastle`), so it also works on web and desktop.

## Quick start

```dart
// Request → server
final body = await Crypto.encryptPayload(
  publicKey: serverPublicKey,               // base64 PEM string from the API
  payload: {'Code': '172', 'Amount': 100.0},
  senderPrivateKey: devicePrivateKey,       // optional: adds "signature"
);
// POST jsonEncode(body) …

// Server → response
final data = Crypto.decryptResponse(
  responseJson,                             // {"payload","key","nonce"[,"signature"]}
  devicePrivateKey,
  senderPublicKey: serverPublicKey,         // optional: signature becomes mandatory
);
```

Byte-level equivalents with an `oaep: true` switch: `Crypto.encryptEnvelope(...)`
and `Crypto.decryptEnvelope(...)`.

### Individual tools

```dart
// Keys (same base64-PEM strings the Go backend uses)
final (privateKey, publicKey) = Crypto.generateRSAKeyPair();

// RSA
final pub = Crypto.fromBase64PublicKey(publicKey);
final priv = Crypto.fromBase64PrivateKey(privateKey);
final ct = pub.encryptWithUint8ListPublicKey(bytes);          // PKCS#1 v1.5
final pt = priv.decryptWithPrivateKey(base64Encode(ct));
final ct2 = pub.encryptWithPublicKeyOAEP(bytes);              // OAEP-SHA256
final pt2 = priv.decryptWithPrivateKeyOAEP(base64Encode(ct2));

// AES-256-GCM
final key = Crypto.generateRandomBytes(32);
final nonce = Crypto.generateNonce();
final (ciphertext, nonceB64) = Crypto.encryptWithAES(key, nonce, utf8Bytes);
final plaintext = Crypto.decryptWithAES(key, ciphertext, nonceB64); // String

// Signatures
final sig = Crypto.sign(privateKey, message);                 // base64
final ok = Crypto.verify(publicKey, message, sig);
final (ct3, nonce3, sig3) =
    Crypto.encryptWithAESandGenerateSignature(key, nonce, plaintext, privateKey);
final valid = Crypto.fromBase64PublicKey(publicKey).verifySignature(ct3, sig3);

// Logging (silent by default)
Crypto.logger = print;
```

Lower-level classes are exported too: `AesGcm` (fast AES-GCM) and
`RsaKeyCodec` (PEM/DER key encoding).

## Compatibility

* Field names in envelopes are matched case-insensitively, so replies from
  older Go servers (`Payload`/`Key`/`Nonce`) open fine.
* Envelopes whose RSA block holds the base64 *text* of the AES key (what this
  package produced before 0.1.0) are still accepted when decrypting.
* Wire format details: `interop/PROTOCOL.md`.

## Performance

Dart is the slowest of the three (pure-Dart big-number and AES code, no
hardware acceleration) but comfortably fast for app traffic: a typical
1 KiB request is encrypted and signed in ~3.5 ms on an Apple M4.

Version 0.1.0 replaced PointyCastle's AES-GCM with a table-based GHASH
(`AesGcm`), taking 1 MiB from **1.29 s down to 0.09 s** (14× faster) while
staying bit-for-bit compatible (NIST vectors, PointyCastle and the Go/Rust
suites all agree).

Mean time per operation on Apple M4 (Darwin). Lower is better.
RSA rows include base64 + PEM parsing of the key on every call, as callers pay it;
the ↳ rows reuse a parsed key object (Rust `PublicKey` / `PrivateKey`).

| Operation | Go | Rust (pure) | Rust (OpenSSL) | Dart (AOT) |
|---|---:|---:|---:|---:|
| RSA-2048 key pair generation | 89.91 ms | 183.03 ms | 47.19 ms | 212.50 ms |
| RSA encrypt, PKCS#1 v1.5 (32-byte AES key) | 45.9 µs | 174.0 µs | 36.3 µs | 187.1 µs |
| RSA decrypt, PKCS#1 v1.5 | 1.56 ms | 1.42 ms | 1.02 ms | 3.04 ms |
|   ↳ encrypt with pre-parsed key object | – | 170.8 µs | 18.4 µs | – |
|   ↳ decrypt with pre-parsed key object | – | 1.36 ms | 630.4 µs | – |
| RSA encrypt, OAEP-SHA256 | 46.0 µs | 177.8 µs | 38.2 µs | 216.3 µs |
| RSA decrypt, OAEP-SHA256 | 1.58 ms | 1.42 ms | 1.02 ms | 3.06 ms |
| AES-256-GCM encrypt, 1 KiB | 2.1 µs | 2.8 µs | 2.8 µs | 96.3 µs |
| AES-256-GCM decrypt, 1 KiB | 1.6 µs | 1.4 µs | 1.4 µs | 96.7 µs |
| AES-256-GCM encrypt, 1 MiB | 1.00 ms (1045 MB/s) | 860.0 µs (1219 MB/s) | 839.6 µs (1249 MB/s) | 90.93 ms (12 MB/s) |
| AES-256-GCM decrypt, 1 MiB | 932.6 µs (1124 MB/s) | 854.4 µs (1227 MB/s) | 842.6 µs (1244 MB/s) | 92.75 ms (11 MB/s) |
| Sign (RSA-SHA256), 1 KiB | 1.59 ms | 1.42 ms | 1.02 ms | 3.20 ms |
| Verify (RSA-SHA256), 1 KiB | 45.1 µs | 175.9 µs | 36.8 µs | 225.2 µs |
| Envelope encrypt + sign, 1 KiB | 1.64 ms | 1.60 ms | 1.06 ms | 3.39 ms |
| Envelope verify + decrypt, 1 KiB | 1.61 ms | 1.59 ms | 1.06 ms | 3.54 ms |
Reproduce with `dart compile exe benchmark/bench.dart -o bench && ./bench`
(AOT, like a Flutter release build) or, for all three languages at once,
`interop/bench.sh`.

## Testing

```bash
flutter test               # unit tests, incl. NIST GCM vectors and a captured production envelope
../interop/run.sh          # cross-language interoperability suite
dart run tool/interop.dart # the CLI used by the suite
```

## License

MIT — see [LICENSE](LICENSE).
