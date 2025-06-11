import 'dart:convert';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:pointycastle/export.dart';
import 'dart:math';

/// A class that provides cryptographic operations such as encryption, decryption,
/// signature generation, and verification using RSA and AES algorithms.
class Crypto {
  final RSAPrivateKey? privateKey;
  final RSAPublicKey? publicKey;

  Crypto._({this.privateKey, this.publicKey});

  /// Creates a [Crypto] instance from a base64 encoded RSA private key.
  ///
  /// Throws an [ArgumentError] if the provided key is not a valid RSA private key.
  ///
  /// Example:
  /// ```dart
  /// final crypto = Crypto.fromBase64PrivateKey(base64PrivateKey);
  /// ```
  factory Crypto.fromBase64PrivateKey(String base64PrivateKey) {
    final pemBytes = base64Decode(base64PrivateKey);
    final pemString = String.fromCharCodes(pemBytes);

    final parser = encrypt.RSAKeyParser();
    final key = parser.parse(pemString);
    if (key is RSAPrivateKey) {
      return Crypto._(privateKey: key);
    } else {
      throw ArgumentError('Invalid RSA Private Key');
    }
  }

  /// Creates a [Crypto] instance from a base64 encoded RSA public key.
  ///
  /// Throws an [ArgumentError] if the provided key is not a valid RSA public key.
  ///
  /// Example:
  /// ```dart
  /// final crypto = Crypto.fromBase64PublicKey(base64PublicKey);
  /// ```
  factory Crypto.fromBase64PublicKey(String base64PublicKey) {
    final pemBytes = base64Decode(base64PublicKey);
    final pemString = String.fromCharCodes(pemBytes);

    final parser = encrypt.RSAKeyParser();
    final key = parser.parse(pemString);
    if (key is RSAPublicKey) {
      return Crypto._(publicKey: key);
    } else {
      throw ArgumentError('Invalid RSA Public Key');
    }
  }

  /// Encrypts a [message] using the RSA public key.
  ///
  /// Throws an [ArgumentError] if the public key is not provided.
  ///
  /// Example:
  /// ```dart
  /// final encryptedMessage = crypto.encryptWithPublicKey('Hello, World!');
  /// ```
  Uint8List encryptWithPublicKey(String message) {
    if (publicKey == null) {
      throw ArgumentError('Public key is required for encryption');
    }

    final cipher = RSAEngine()
      ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey!));

    final messageBytes = utf8.encode(message);
    return _processBlocks(cipher, Uint8List.fromList(messageBytes));
  }

  /// Decrypts an [encryptedMessage] using the RSA private key.
  ///
  /// Throws an [ArgumentError] if the private key is not provided.
  ///
  /// Example:
  /// ```dart
  /// final decryptedMessage = crypto.decryptWithPrivateKey(encryptedMessage);
  /// ```
  Uint8List decryptWithPrivateKey(String encryptedMessage) {
    if (privateKey == null) {
      throw ArgumentError('Private key is required for decryption');
    }

    final encryptedBytes = base64Decode(encryptedMessage);

    final cipher = RSAEngine()
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey!));

    return _processBlocks(cipher, encryptedBytes);
  }

  /// Generates a random nonce for AES-GCM encryption.
  ///
  /// Example:
  /// ```dart
  /// final nonce = Crypto.generateNonce();
  /// ```
  static Uint8List generateNonce() {
    final secureRandom = FortunaRandom();
    final random = Random.secure();
    secureRandom.seed(KeyParameter(
        Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)))));
    final nonce = Uint8List(12); // AES-GCM nonce size

    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = random.nextInt(256);
    }
    return nonce;
  }

  /// Verifies the [signature] of an [encryptedMessage] using the RSA public key.
  ///
  /// Throws an [ArgumentError] if the public key is not provided.
  ///
  /// Example:
  /// ```dart
  /// final isValid = crypto.verifySignature(encryptedMessage, signature);
  /// ```
  bool verifySignature(String encryptedMessage, String signature) {
    if (publicKey == null) {
      throw ArgumentError('Public key is required for signature verification');
    }

    final signer = Signer("SHA-256/RSA");
    signer.init(false, PublicKeyParameter<RSAPublicKey>(publicKey!));

    final ciphertextBytes = base64Decode(encryptedMessage);
    final signatureBytes = base64Decode(signature);

    return signer.verifySignature(
        Uint8List.fromList(ciphertextBytes), RSASignature(signatureBytes));
  }

  /// Encrypts [plaintext] with AES and generates a signature using the device's private key.
  ///
  /// Returns a tuple containing the ciphertext, nonce, and signature.
  ///
  /// Example:
  /// ```dart
  /// final (ciphertext, nonce, signature) = Crypto.encryptWithAESandGenerateSignature(key, nonce, plaintext, devicePrivateKeyStr);
  /// ```
  static (String, String, String) encryptWithAESandGenerateSignature(
      Uint8List key, Uint8List nonce, Uint8List plaintext, String devicePrivateKeyStr) {
    final gcm = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));

    final ciphertextBytes = gcm.process(plaintext);
    final ciphertext = base64Encode(ciphertextBytes);

    final signer = RSASigner(Digest('SHA-256'), '0609608648016503040201');
    final privateKey = Crypto.fromBase64PrivateKey(devicePrivateKeyStr).privateKey!;
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final signature = signer.generateSignature(Uint8List.fromList(ciphertextBytes));

    final signatureBase64 = base64Encode(signature.bytes);

    return (ciphertext, base64Encode(nonce), signatureBase64);
  }

  /// Encrypts [plaintext] with AES.
  ///
  /// Returns a tuple containing the ciphertext and nonce.
  ///
  /// Example:
  /// ```dart
  /// final (ciphertext, nonce) = Crypto.encryptWithAES(key, nonce, plaintext);
  /// ```
  static (String, String) encryptWithAES(Uint8List key, Uint8List nonce, Uint8List plaintext) {
    final gcm = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));

    final ciphertextBytes = gcm.process(plaintext);
    final ciphertext = base64Encode(ciphertextBytes);

    return (ciphertext, base64Encode(nonce));
  }

  /// Decrypts [cipherText] with AES using the provided [key] and [nonceText].
  ///
  /// Example:
  /// ```dart
  /// final plaintext = Crypto.decryptWithAES(key, cipherText, nonceText);
  /// ```
  static String decryptWithAES(Uint8List key, String cipherText, String nonceText) {
    final ciphertextBytes = base64Decode(cipherText);
    final nonce = base64Decode(nonceText);

    final gcm = GCMBlockCipher(AESEngine())
      ..init(false, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));

    final plaintextBytes = gcm.process(ciphertextBytes);

    return String.fromCharCodes(plaintextBytes);
  }

  /// Generates random bytes of the specified [length].
  ///
  /// Example:
  /// ```dart
  /// final randomBytes = Crypto.generateRandomBytes(16);
  /// ```
  static Uint8List generateRandomBytes(int length) {
    final random = Random.secure();
    final key = Uint8List(length);

    for (int i = 0; i < length; i++) {
      key[i] = random.nextInt(256);
    }

    return key;
  }

  /// Processes the input bytes in blocks using the provided [cipher].
  ///
  /// Example:
  /// ```dart
  /// final processedBytes = Crypto._processBlocks(cipher, inputBytes);
  /// ```
  static Uint8List _processBlocks(AsymmetricBlockCipher cipher, Uint8List inputBytes) {
    final blockSize = cipher.inputBlockSize;
    final outputBytes = <int>[];

    for (var offset = 0; offset < inputBytes.length; offset += blockSize) {
      final end = (offset + blockSize < inputBytes.length)
          ? offset + blockSize
          : inputBytes.length;
      final block = inputBytes.sublist(offset, end);

      final processedBlock = cipher.process(Uint8List.fromList(block));
      outputBytes.addAll(processedBlock);
    }

    return Uint8List.fromList(outputBytes);
  }

  /// Signs a message using a base64-encoded RSA private key. Returns the signature as Uint8List.
  static Uint8List signWithPrivateKey(String privateKeyBase64, Uint8List message) {
    final pemBytes = base64Decode(privateKeyBase64);
    final pemString = String.fromCharCodes(pemBytes);
    final parser = encrypt.RSAKeyParser();
    final key = parser.parse(pemString);
    if (key is! RSAPrivateKey) {
      throw ArgumentError('Invalid RSA Private Key');
    }
    final signer = Signer("SHA-256/RSA");
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(key));
    final sig = signer.generateSignature(message) as RSASignature;
    return sig.bytes;
  }

  /// Verifies a signature using a base64-encoded RSA public key. Returns true if valid.
  static bool verifyWithPublicKey(String publicKeyBase64, Uint8List message, Uint8List signature) {
    final pemBytes = base64Decode(publicKeyBase64);
    final pemString = String.fromCharCodes(pemBytes);
    final parser = encrypt.RSAKeyParser();
    final key = parser.parse(pemString);
    if (key is! RSAPublicKey) {
      throw ArgumentError('Invalid RSA Public Key');
    }
    final signer = Signer("SHA-256/RSA");
    signer.init(false, PublicKeyParameter<RSAPublicKey>(key));
    return signer.verifySignature(message, RSASignature(signature));
  }
}
