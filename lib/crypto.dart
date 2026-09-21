import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'src/aes_gcm.dart';
import 'src/rsa_keys.dart';

/// Optional log sink. Set `Crypto.logger = print;` (or a real logger) to see
/// diagnostic messages; by default the library is silent.
typedef CryptoLogger = void Function(String message);

/// RSA + AES-GCM helpers that interoperate with the Go `crypto_utils` package
/// and the Rust `crypto_utils` crate.
///
/// Wire format shared by all implementations:
///
/// * Keys are RSA-2048 transported as base64(PEM): PKCS#1 `RSA PRIVATE KEY`
///   for private keys, PKIX `PUBLIC KEY` for public keys.
/// * RSA encryption uses PKCS#1 v1.5 by default; RSA-OAEP with SHA-256 is
///   available through the `*OAEP` methods.
/// * Symmetric encryption is AES-256-GCM, 12-byte nonce, 128-bit tag appended
///   to the ciphertext, no additional authenticated data.
/// * Signatures are RSASSA-PKCS1-v1_5 over the SHA-256 digest of the message.
/// * The hybrid envelope is a JSON map with base64 strings: `key` (RSA-encrypted
///   raw 32-byte AES key), `nonce`, `payload` (GCM ciphertext) and an optional
///   `signature` over the raw ciphertext bytes.
class Crypto {
  /// AES-256 key length in bytes.
  static const int aesKeySize = 32;

  /// AES-GCM nonce length in bytes.
  static const int gcmNonceSize = 12;

  /// Default RSA modulus size for [generateRSAKeyPair].
  static const int rsaKeyBits = 2048;

  /// Diagnostic sink; `null` (the default) disables logging.
  static CryptoLogger? logger;

  final RSAPrivateKey? privateKey;
  final RSAPublicKey? publicKey;

  Crypto._({this.privateKey, this.publicKey});

  static void _log(String message) => logger?.call(message);

  // ------------------------------------------------------------------- keys

  /// Creates a [Crypto] instance from a base64 encoded RSA private key PEM.
  ///
  /// Throws an [ArgumentError] if the key cannot be parsed.
  factory Crypto.fromBase64PrivateKey(String base64PrivateKey) {
    try {
      return Crypto._(
        privateKey: RsaKeyCodec.parsePrivateKeyBase64(base64PrivateKey),
      );
    } on FormatException catch (e) {
      throw ArgumentError('Invalid RSA Private Key: ${e.message}');
    }
  }

  /// Creates a [Crypto] instance from a base64 encoded RSA public key PEM.
  ///
  /// Throws an [ArgumentError] if the key cannot be parsed.
  factory Crypto.fromBase64PublicKey(String base64PublicKey) {
    try {
      return Crypto._(
        publicKey: RsaKeyCodec.parsePublicKeyBase64(base64PublicKey),
      );
    } on FormatException catch (e) {
      throw ArgumentError('Invalid RSA Public Key: ${e.message}');
    }
  }

  /// Generates an RSA key pair and returns `(privateKey, publicKey)` as
  /// base64(PEM) strings in the same format as the Go and Rust libraries.
  static (String, String) generateRSAKeyPair({int bitLength = rsaKeyBits}) {
    final generator = RSAKeyGenerator()
      ..init(
        ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.from(65537), bitLength, 64),
          _secureRandom(),
        ),
      );
    final pair = generator.generateKeyPair();
    return (
      RsaKeyCodec.encodePrivateKeyBase64(pair.privateKey),
      RsaKeyCodec.encodePublicKeyBase64(pair.publicKey),
    );
  }

  // ------------------------------------------------------------------ random

  /// Generates [length] cryptographically secure random bytes.
  static Uint8List generateRandomBytes(int length) {
    final random = Random.secure();
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = random.nextInt(256);
    }
    return bytes;
  }

  /// Generates a random 12-byte AES-GCM nonce.
  static Uint8List generateNonce() => generateRandomBytes(gcmNonceSize);

  static SecureRandom _secureRandom() {
    final random = FortunaRandom()..seed(KeyParameter(generateRandomBytes(32)));
    return random;
  }

  // --------------------------------------------------------------------- RSA

  /// Encrypts [message] with the RSA public key using PKCS#1 v1.5 padding and
  /// returns the raw ciphertext bytes.
  Uint8List encryptWithUint8ListPublicKey(Uint8List message) {
    final key = _requirePublicKey('encryption');
    final maxLength = (key.modulus!.bitLength + 7) ~/ 8 - 11;
    if (message.length > maxLength) {
      throw ArgumentError(
        'Message too large for RSA encryption. Max: $maxLength, Got: ${message.length}',
      );
    }
    final cipher = PKCS1Encoding(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(key));
    return cipher.process(message);
  }

  /// Encrypts the UTF-8 bytes of [message] with the RSA public key
  /// (PKCS#1 v1.5) and returns the raw ciphertext bytes.
  Uint8List encryptWithPublicKey(String message) =>
      encryptWithUint8ListPublicKey(Uint8List.fromList(utf8.encode(message)));

  /// Encrypts [message] with the RSA public key using OAEP (SHA-256, MGF1-SHA256,
  /// empty label) and returns the raw ciphertext bytes.
  Uint8List encryptWithPublicKeyOAEP(Uint8List message) {
    final key = _requirePublicKey('encryption');
    final cipher = OAEPEncoding.withSHA256(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(key));
    return cipher.process(message);
  }

  /// Decrypts a base64 RSA PKCS#1 v1.5 ciphertext with the private key and
  /// returns the plaintext bytes (padding removed).
  Uint8List decryptWithPrivateKey(String encryptedMessage) {
    final key = _requirePrivateKey('decryption');
    final cipher = PKCS1Encoding(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(key));
    return cipher.process(_b64(encryptedMessage, 'encrypted message'));
  }

  /// Decrypts a base64 RSA-OAEP (SHA-256) ciphertext with the private key.
  Uint8List decryptWithPrivateKeyOAEP(String encryptedMessage) {
    final key = _requirePrivateKey('decryption');
    final cipher = OAEPEncoding.withSHA256(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(key));
    return cipher.process(_b64(encryptedMessage, 'encrypted message'));
  }

  // ----------------------------------------------------------------- AES-GCM

  /// Encrypts [plaintext] with AES-256-GCM and returns the raw ciphertext with
  /// the 16-byte tag appended.
  static Uint8List encryptWithAESBytes(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
  ) {
    _checkAesParams(key, nonce);
    return AesGcm(key).encrypt(nonce, plaintext);
  }

  /// Decrypts raw AES-256-GCM [ciphertext] (tag appended) and returns the
  /// plaintext bytes. Throws if the key is wrong or the data was tampered with.
  static Uint8List decryptWithAESBytes(
    Uint8List key,
    Uint8List nonce,
    Uint8List ciphertext,
  ) {
    _checkAesParams(key, nonce);
    return AesGcm(key).decrypt(nonce, ciphertext);
  }

  /// Encrypts [plaintext] with AES-256-GCM.
  ///
  /// Returns `(base64 ciphertext, base64 nonce)`.
  static (String, String) encryptWithAES(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
  ) {
    final ciphertext = encryptWithAESBytes(key, nonce, plaintext);
    return (base64Encode(ciphertext), base64Encode(nonce));
  }

  /// Encrypts [plaintext] with AES-256-GCM and signs the raw ciphertext with
  /// [devicePrivateKeyStr] (base64 PEM).
  ///
  /// Returns `(base64 ciphertext, base64 nonce, base64 signature)`.
  static (String, String, String) encryptWithAESandGenerateSignature(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
    String devicePrivateKeyStr,
  ) {
    final ciphertext = encryptWithAESBytes(key, nonce, plaintext);
    final signature = signWithPrivateKey(devicePrivateKeyStr, ciphertext);
    return (
      base64Encode(ciphertext),
      base64Encode(nonce),
      base64Encode(signature),
    );
  }

  /// Decrypts base64 AES-256-GCM [cipherText] with base64 [nonceText] and
  /// returns the plaintext as a UTF-8 string.
  static String decryptWithAES(
    Uint8List key,
    String cipherText,
    String nonceText,
  ) {
    return utf8.decode(
      decryptWithAESBytes(
        key,
        _b64(nonceText, 'nonce'),
        _b64(cipherText, 'ciphertext'),
      ),
    );
  }

  /// Alias of [decryptWithAES], kept for backward compatibility.
  static String decryptWithAESGCM(
    Uint8List key,
    String cipherText,
    String nonceText,
  ) =>
      decryptWithAES(key, cipherText, nonceText);

  static void _checkAesParams(Uint8List key, Uint8List nonce) {
    if (key.length != aesKeySize) {
      throw ArgumentError(
          'AES key must be $aesKeySize bytes, got ${key.length}');
    }
    if (nonce.length != gcmNonceSize) {
      throw ArgumentError(
        'AES-GCM nonce must be $gcmNonceSize bytes, got ${nonce.length}',
      );
    }
  }

  // -------------------------------------------------------------- signatures

  /// Signs [message] (RSASSA-PKCS1-v1_5 / SHA-256) with a base64 PEM private
  /// key and returns the raw signature bytes.
  static Uint8List signWithPrivateKey(
    String privateKeyBase64,
    Uint8List message,
  ) {
    final key = Crypto.fromBase64PrivateKey(privateKeyBase64).privateKey!;
    final signer = Signer('SHA-256/RSA')
      ..init(true, PrivateKeyParameter<RSAPrivateKey>(key));
    return (signer.generateSignature(message) as RSASignature).bytes;
  }

  /// Signs [message] and returns the signature as base64.
  static String sign(String privateKeyBase64, Uint8List message) =>
      base64Encode(signWithPrivateKey(privateKeyBase64, message));

  /// Verifies a raw RSASSA-PKCS1-v1_5 / SHA-256 [signature] over [message]
  /// with a base64 PEM public key.
  static bool verifyWithPublicKey(
    String publicKeyBase64,
    Uint8List message,
    Uint8List signature,
  ) {
    final key = Crypto.fromBase64PublicKey(publicKeyBase64).publicKey!;
    return _verify(key, message, signature);
  }

  /// Verifies a base64 [signatureBase64] over [message] with a base64 PEM
  /// public key.
  static bool verify(
    String publicKeyBase64,
    Uint8List message,
    String signatureBase64,
  ) =>
      verifyWithPublicKey(
        publicKeyBase64,
        message,
        _b64(signatureBase64, 'signature'),
      );

  /// Verifies the base64 [signature] over the raw bytes of the base64
  /// [encryptedMessage] using this instance's public key.
  bool verifySignature(String encryptedMessage, String signature) {
    final key = _requirePublicKey('signature verification');
    return _verify(
      key,
      _b64(encryptedMessage, 'encrypted message'),
      _b64(signature, 'signature'),
    );
  }

  static bool _verify(RSAPublicKey key, Uint8List message, Uint8List sig) {
    final signer = Signer('SHA-256/RSA')
      ..init(false, PublicKeyParameter<RSAPublicKey>(key));
    try {
      return signer.verifySignature(message, RSASignature(sig));
    } catch (_) {
      return false;
    }
  }

  // ---------------------------------------------------------------- envelope

  /// Builds a hybrid envelope for [payload]: a fresh AES-256 key encrypts the
  /// payload with GCM and the raw key is RSA-encrypted for [recipientPublicKey].
  ///
  /// Pass [senderPrivateKey] to add a `signature` over the raw ciphertext and
  /// `oaep: true` to wrap the AES key with RSA-OAEP instead of PKCS#1 v1.5.
  static Map<String, String> encryptEnvelope({
    required String recipientPublicKey,
    required Uint8List payload,
    String? senderPrivateKey,
    bool oaep = false,
  }) {
    final aesKey = generateRandomBytes(aesKeySize);
    final nonce = generateNonce();
    final ciphertext = encryptWithAESBytes(aesKey, nonce, payload);

    final recipient = Crypto.fromBase64PublicKey(recipientPublicKey);
    final encryptedKey = oaep
        ? recipient.encryptWithPublicKeyOAEP(aesKey)
        : recipient.encryptWithUint8ListPublicKey(aesKey);

    final envelope = <String, String>{
      'payload': base64Encode(ciphertext),
      'key': base64Encode(encryptedKey),
      'nonce': base64Encode(nonce),
    };
    if (senderPrivateKey != null) {
      envelope['signature'] = sign(senderPrivateKey, ciphertext);
    }
    _log('Envelope built: ${ciphertext.length} ciphertext bytes');
    return envelope;
  }

  /// Opens a hybrid [envelope] with [recipientPrivateKey].
  ///
  /// Field names are matched case-insensitively (`payload`/`Payload`, ...).
  /// When [senderPublicKey] is given the `signature` field is required and
  /// must verify over the raw ciphertext. Set `oaep: true` for envelopes whose
  /// key was wrapped with RSA-OAEP.
  ///
  /// For backward compatibility a key that decrypts to the 44-character
  /// base64 text of the AES key (older clients) is accepted as well.
  static Uint8List decryptEnvelope({
    required String recipientPrivateKey,
    required Map<String, dynamic> envelope,
    String? senderPublicKey,
    bool oaep = false,
  }) {
    final encryptedKey = _field(envelope, 'key');
    final payload = _field(envelope, 'payload');
    final nonceText = _field(envelope, 'nonce');
    if (encryptedKey == null || payload == null || nonceText == null) {
      throw ArgumentError('Envelope is missing key, payload or nonce');
    }

    final ciphertext = _b64(payload, 'payload');
    final nonce = _b64(nonceText, 'nonce');

    if (senderPublicKey != null) {
      final signature = _field(envelope, 'signature');
      if (signature == null) {
        throw ArgumentError('Envelope has no signature');
      }
      if (!verify(senderPublicKey, ciphertext, signature)) {
        throw StateError('Envelope signature verification failed');
      }
    }

    final recipient = Crypto.fromBase64PrivateKey(recipientPrivateKey);
    final rawKey = oaep
        ? recipient.decryptWithPrivateKeyOAEP(encryptedKey)
        : recipient.decryptWithPrivateKey(encryptedKey);
    final aesKey = _normalizeAesKey(rawKey);

    return decryptWithAESBytes(aesKey, nonce, ciphertext);
  }

  static Uint8List _normalizeAesKey(Uint8List raw) {
    if (raw.length == aesKeySize) {
      return raw;
    }
    if (raw.length == 44) {
      try {
        final decoded = base64Decode(ascii.decode(raw));
        if (decoded.length == aesKeySize) {
          _log('Accepted legacy base64-text AES key');
          return decoded;
        }
      } on FormatException {
        // fall through
      }
    }
    throw StateError('Decrypted AES key has unexpected length ${raw.length}');
  }

  static String? _field(Map<String, dynamic> map, String name) {
    for (final entry in map.entries) {
      if (entry.key.toLowerCase() == name) {
        return entry.value as String?;
      }
    }
    return null;
  }

  /// Encrypts a JSON [payload] for the server identified by [publicKey].
  ///
  /// Returns `{"payload", "key", "nonce"}` — the request body expected by the
  /// Go backend's `DecryptPayload`.
  static Future<Map<String, dynamic>> encryptPayload({
    required String publicKey,
    required Map<String, dynamic> payload,
    String? senderPrivateKey,
  }) async {
    return encryptEnvelope(
      recipientPublicKey: publicKey,
      payload: Uint8List.fromList(utf8.encode(json.encode(payload))),
      senderPrivateKey: senderPrivateKey,
    );
  }

  /// Decrypts a server [response] envelope with [serverPrivateKeyBase64] and
  /// parses the plaintext as a JSON object. Pass [senderPublicKey] to require
  /// a valid signature.
  static Map<String, dynamic> decryptResponse(
    Map<String, dynamic> response,
    String serverPrivateKeyBase64, {
    String? senderPublicKey,
  }) {
    final plaintext = decryptEnvelope(
      recipientPrivateKey: serverPrivateKeyBase64,
      envelope: response,
      senderPublicKey: senderPublicKey,
    );
    return jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
  }

  // ---------------------------------------------------------------- helpers

  RSAPublicKey _requirePublicKey(String operation) {
    final key = publicKey;
    if (key == null) {
      throw ArgumentError('Public key is required for $operation');
    }
    return key;
  }

  RSAPrivateKey _requirePrivateKey(String operation) {
    final key = privateKey;
    if (key == null) {
      throw ArgumentError('Private key is required for $operation');
    }
    return key;
  }

  static Uint8List _b64(String value, String what) {
    try {
      return base64Decode(value.trim());
    } on FormatException catch (e) {
      throw ArgumentError('$what is not valid base64: ${e.message}');
    }
  }
}
