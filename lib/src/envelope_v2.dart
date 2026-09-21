import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;

import '../crypto.dart' show Crypto;

/// Envelope v2: X25519 key agreement + HKDF-SHA256 + AES-256-GCM, with an
/// optional Ed25519 signature. Roughly 30× cheaper per message than the RSA
/// envelope, with 32-byte keys. Keys are transported as base64 of their raw
/// 32 bytes (not PEM).
///
/// The API is asynchronous because the underlying `cryptography` package is.
/// In pure Dart the curve arithmetic is slow (about RSA speed overall); in a
/// Flutter app add the `cryptography_flutter` plugin and call
/// `FlutterCryptography.enable()` at start-up to run X25519/Ed25519 on the
/// platform's native crypto (tens of microseconds) — no other change needed.
/// See `interop/PROTOCOL.md`, "Envelope v2".
class CryptoV2 {
  CryptoV2._();

  /// Value of the `v` field.
  static const int version = 2;

  /// HKDF info prefix; the ephemeral and recipient public keys are appended.
  static const String infoPrefix = 'crypto_utils/v2/x25519-aes256gcm';

  /// Byte length of X25519 / Ed25519 public keys and seeds.
  static const int curveKeySize = 32;

  static final c.X25519 _x25519 = c.X25519();
  static final c.Ed25519 _ed25519 = c.Ed25519();
  static final c.Hkdf _hkdf =
      c.Hkdf(hmac: c.Hmac.sha256(), outputLength: Crypto.aesKeySize);

  // ------------------------------------------------------------------- keys

  /// Generates an X25519 key pair as `(privateKey, publicKey)` base64 strings.
  static Future<(String, String)> generateX25519KeyPair() async {
    final seed = Crypto.generateRandomBytes(curveKeySize);
    final pair = await _x25519.newKeyPairFromSeed(seed);
    final pub = await pair.extractPublicKey();
    return (base64Encode(seed), base64Encode(pub.bytes));
  }

  /// Generates an Ed25519 key pair as `(privateSeed, publicKey)` base64 strings.
  static Future<(String, String)> generateEd25519KeyPair() async {
    final seed = Crypto.generateRandomBytes(curveKeySize);
    final pair = await _ed25519.newKeyPairFromSeed(seed);
    final pub = await pair.extractPublicKey();
    return (base64Encode(seed), base64Encode(pub.bytes));
  }

  static Uint8List _curveKey(String b64, String what) {
    final Uint8List raw;
    try {
      raw = base64Decode(b64.trim());
    } on FormatException catch (e) {
      throw ArgumentError('$what is not valid base64: ${e.message}');
    }
    if (raw.length != curveKeySize) {
      throw ArgumentError(
          '$what must be $curveKeySize bytes, got ${raw.length}');
    }
    return raw;
  }

  // ------------------------------------------------------------- signatures

  /// Signs [message] with a base64 Ed25519 seed; returns the base64 signature.
  static Future<String> signEd25519(
      String privateSeedBase64, Uint8List message) async {
    final pair = await _ed25519
        .newKeyPairFromSeed(_curveKey(privateSeedBase64, 'Ed25519 seed'));
    final signature = await _ed25519.sign(message, keyPair: pair);
    return base64Encode(signature.bytes);
  }

  /// Verifies a base64 Ed25519 signature with a base64 public key. A
  /// malformed signature is simply invalid.
  static Future<bool> verifyEd25519(
      String publicKeyBase64, Uint8List message, String signatureBase64) {
    final Uint8List signature;
    try {
      signature = base64Decode(signatureBase64.trim());
    } on FormatException {
      return Future.value(false);
    }
    return _verify(
        _curveKey(publicKeyBase64, 'Ed25519 public key'), message, signature);
  }

  static Future<bool> _verify(
      Uint8List publicKey, Uint8List message, Uint8List signature) async {
    if (signature.length != 64) return false;
    return _ed25519.verify(
      message,
      signature: c.Signature(
        signature,
        publicKey: c.SimplePublicKey(publicKey, type: c.KeyPairType.ed25519),
      ),
    );
  }

  // --------------------------------------------------------------- envelope

  /// Builds a v2 envelope for [recipientX25519PublicKey] (base64 raw), signed
  /// with [senderEd25519PrivateKey] (base64 seed) when given.
  static Future<Map<String, dynamic>> encryptEnvelope({
    required String recipientX25519PublicKey,
    required Uint8List payload,
    String? senderEd25519PrivateKey,
  }) async {
    final recipientPk =
        _curveKey(recipientX25519PublicKey, 'X25519 public key');
    final ephemeralSeed = Crypto.generateRandomBytes(curveKeySize);
    final ephemeral = await _x25519.newKeyPairFromSeed(ephemeralSeed);
    final epk = Uint8List.fromList((await ephemeral.extractPublicKey()).bytes);

    final aesKey = await _deriveKey(ephemeral, recipientPk, epk, recipientPk);
    final nonce = Crypto.generateNonce();
    final ciphertext = Crypto.encryptWithAESBytes(aesKey, nonce, payload);

    final envelope = <String, dynamic>{
      'v': version,
      'epk': base64Encode(epk),
      'nonce': base64Encode(nonce),
      'payload': base64Encode(ciphertext),
    };
    if (senderEd25519PrivateKey != null) {
      envelope['signature'] = await signEd25519(
          senderEd25519PrivateKey, _signedData(epk, nonce, ciphertext));
    }
    return envelope;
  }

  /// Opens a v2 [envelope] with [recipientX25519PrivateKey] (base64 raw).
  /// When [senderEd25519PublicKey] is given the signature is required and
  /// verified before decryption.
  static Future<Uint8List> decryptEnvelope({
    required String recipientX25519PrivateKey,
    required Map<String, dynamic> envelope,
    String? senderEd25519PublicKey,
  }) async {
    final epkText = envelope['epk'] as String?;
    final nonceText = envelope['nonce'] as String?;
    final payloadText = envelope['payload'] as String?;
    if (epkText == null || nonceText == null || payloadText == null) {
      throw ArgumentError('Envelope is missing epk, nonce or payload');
    }
    final v = envelope['v'];
    if (v != version) {
      throw ArgumentError('Unsupported envelope version $v');
    }
    final epk = _curveKey(epkText, 'epk');
    final nonce = base64Decode(nonceText);
    final ciphertext = base64Decode(payloadText);

    if (senderEd25519PublicKey != null) {
      final signature = envelope['signature'] as String?;
      if (signature == null) {
        throw ArgumentError('Envelope has no signature');
      }
      if (!await verifyEd25519(senderEd25519PublicKey,
          _signedData(epk, nonce, ciphertext), signature)) {
        throw StateError('Envelope signature verification failed');
      }
    }

    final recipient = await _x25519.newKeyPairFromSeed(
        _curveKey(recipientX25519PrivateKey, 'X25519 private key'));
    final recipientPk =
        Uint8List.fromList((await recipient.extractPublicKey()).bytes);
    final aesKey = await _deriveKey(recipient, epk, epk, recipientPk);
    return Crypto.decryptWithAESBytes(aesKey, nonce, ciphertext);
  }

  /// JSON convenience: encrypts `json.encode(payload)` for the server.
  static Future<Map<String, dynamic>> encryptPayload({
    required String recipientX25519PublicKey,
    required Map<String, dynamic> payload,
    String? senderEd25519PrivateKey,
  }) =>
      encryptEnvelope(
        recipientX25519PublicKey: recipientX25519PublicKey,
        payload: Uint8List.fromList(utf8.encode(json.encode(payload))),
        senderEd25519PrivateKey: senderEd25519PrivateKey,
      );

  /// JSON convenience: decrypts a v2 envelope and parses the JSON object.
  static Future<Map<String, dynamic>> decryptResponse(
    Map<String, dynamic> envelope,
    String recipientX25519PrivateKey, {
    String? senderEd25519PublicKey,
  }) async {
    final plaintext = await decryptEnvelope(
      recipientX25519PrivateKey: recipientX25519PrivateKey,
      envelope: envelope,
      senderEd25519PublicKey: senderEd25519PublicKey,
    );
    return jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
  }

  /// HKDF-SHA256(X25519(ours, theirs), salt = "", info = prefix || epk || recipientPk).
  static Future<Uint8List> _deriveKey(c.KeyPair ours, Uint8List theirPublicKey,
      Uint8List epk, Uint8List recipientPk) async {
    final shared = await _x25519.sharedSecretKey(
      keyPair: ours,
      remotePublicKey:
          c.SimplePublicKey(theirPublicKey, type: c.KeyPairType.x25519),
    );
    final sharedBytes = await shared.extractBytes();
    if (sharedBytes.every((b) => b == 0)) {
      throw StateError('X25519 produced an all-zero shared secret');
    }
    final info = <int>[...utf8.encode(infoPrefix), ...epk, ...recipientPk];
    final key = await _hkdf.deriveKey(
        secretKey: c.SecretKey(sharedBytes), nonce: const [], info: info);
    return Uint8List.fromList(await key.extractBytes());
  }

  /// epk || nonce || ciphertext
  static Uint8List _signedData(
          Uint8List epk, Uint8List nonce, Uint8List ciphertext) =>
      Uint8List.fromList([...epk, ...nonce, ...ciphertext]);
}
