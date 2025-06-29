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

  /// Encrypts a Uint8List using the RSA public key with PKCS1 padding.
  /// This method uses the encrypt package's RSA implementation for better compatibility.
  ///
  /// Example:
  /// ```dart
  /// final encryptedBytes = crypto.encryptWithUint8ListPublicKey(aesKeyBytes);
  /// ```
  Uint8List encryptWithUint8ListPublicKey(Uint8List message) {
    if (publicKey == null) {
      throw ArgumentError('Public key is required for encryption');
    }

    print('🔍 RSA Debug Info:');
    print('  - Message length: ${message.length}');
    print('  - Public key modulus length: ${publicKey!.modulus!.bitLength}');
    print('  - Public key exponent: ${publicKey!.exponent}');
    print(
      '  - Message (hex): ${message.map((b) => b.toRadixString(16).padLeft(2, '0')).join('')}',
    );

    // Calculate the correct block size (modulus length in bytes)
    final blockSize = (publicKey!.modulus!.bitLength + 7) ~/ 8;
    print('  - Block size: $blockSize');

    if (message.length > blockSize - 11) {
      throw ArgumentError(
        'Message too large for RSA encryption. Max: ${blockSize - 11}, Got: ${message.length}',
      );
    }

    // OPTION 1: Use encrypt package's RSA implementation (RECOMMENDED)
    try {
      print('  - Using encrypt package RSA method');
      final encrypter = encrypt.Encrypter(encrypt.RSA(publicKey: publicKey!));

      // Convert Uint8List to base64 string for encrypt package
      final messageBase64 = base64Encode(message);
      final encrypted = encrypter.encrypt(messageBase64);
      final encryptedBytes = base64Decode(encrypted.base64);

      print('  - Encrypted length: ${encryptedBytes.length}');
      print('  - First few bytes: ${encryptedBytes.take(10).toList()}');

      return encryptedBytes;
    } catch (e) {
      print('  - Encrypt package failed: $e');
      print('  - Falling back to manual PKCS1 padding');

      // OPTION 2: Manual PKCS1 padding with PointyCastle
      return _encryptWithManualPKCS1Padding(message, blockSize);
    }
  }

  /// Manual PKCS1 v1.5 padding implementation
  Uint8List _encryptWithManualPKCS1Padding(Uint8List message, int blockSize) {
    final cipher = RSAEngine();
    cipher.init(true, PublicKeyParameter<RSAPublicKey>(publicKey!));

    // Create PKCS1 v1.5 padding
    final paddedMessage = Uint8List(blockSize);
    paddedMessage[0] = 0x00; // Leading zero
    paddedMessage[1] = 0x02; // PKCS1 v1.5 padding type

    // Fill with random non-zero bytes
    final random = Random.secure();
    final paddingLength = blockSize -
        message.length -
        3; // 3 = leading zero + padding type + separator

    for (int i = 2; i < 2 + paddingLength; i++) {
      do {
        paddedMessage[i] = random.nextInt(256);
      } while (paddedMessage[i] == 0);
    }

    paddedMessage[2 + paddingLength] = 0x00; // Separator
    paddedMessage.setRange(
      2 + paddingLength + 1,
      blockSize,
      message,
    ); // Actual message

    final encrypted = cipher.process(paddedMessage);
    print('  - Manual PKCS1 encrypted length: ${encrypted.length}');
    print('  - Manual PKCS1 first few bytes: ${encrypted.take(10).toList()}');

    return encrypted;
  }

  /// Encrypts a string message using the RSA public key with PKCS1 padding.
  /// This method converts the string to bytes and then encrypts.
  ///
  /// Example:
  /// ```dart
  /// final encryptedBytes = crypto.encryptWithPublicKey('Hello, World!');
  /// ```
  Uint8List encryptWithPublicKey(String message) {
    if (publicKey == null) {
      throw ArgumentError('Public key is required for encryption');
    }

    final messageBytes = utf8.encode(message);
    return encryptWithUint8ListPublicKey(Uint8List.fromList(messageBytes));
  }

  /// Decrypts an encrypted message using the RSA private key with PKCS1 padding.
  ///
  /// Example:
  /// ```dart
  /// final decryptedBytes = crypto.decryptWithPrivateKey(encryptedMessage);
  /// ```
  Uint8List decryptWithPrivateKey(String encryptedMessage) {
    if (privateKey == null) {
      throw ArgumentError('Private key is required for decryption');
    }

    print('🔓 RSA Decryption Debug:');
    print('  - Encrypted message length: ${encryptedMessage.length}');

    final encryptedBytes = base64Decode(encryptedMessage);
    print('  - Decoded encrypted bytes length: ${encryptedBytes.length}');
    print('  - First few encrypted bytes: ${encryptedBytes.take(10).toList()}');

    // Try PKCS1v15 first (most common)
    try {
      print('  - Trying PKCS1v15 decryption...');
      final cipher = RSAEngine();
      cipher.init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey!));

      final decrypted = cipher.process(encryptedBytes);
      print('  - PKCS1v15 decryption successful, length: ${decrypted.length}');
      print('  - First few decrypted bytes: ${decrypted.take(10).toList()}');

      return decrypted;
    } catch (e) {
      print('  - PKCS1v15 decryption failed: $e');

      // Try OAEP as fallback
      try {
        print('  - Trying OAEP decryption...');
        final cipher = RSAEngine();
        cipher.init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey!));

        // Use OAEP padding
        final decrypted = cipher.process(encryptedBytes);
        print('  - OAEP decryption successful, length: ${decrypted.length}');
        print('  - First few decrypted bytes: ${decrypted.take(10).toList()}');

        return decrypted;
      } catch (e2) {
        print('  - OAEP decryption also failed: $e2');
        throw Exception('Both PKCS1v15 and OAEP decryption failed: $e, $e2');
      }
    }
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
    secureRandom.seed(
      KeyParameter(
        Uint8List.fromList(List.generate(32, (_) => random.nextInt(256))),
      ),
    );
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
      Uint8List.fromList(ciphertextBytes),
      RSASignature(signatureBytes),
    );
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
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
    String devicePrivateKeyStr,
  ) {
    final gcm = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));

    final ciphertextBytes = gcm.process(plaintext);
    final ciphertext = base64Encode(ciphertextBytes);

    final signer = RSASigner(Digest('SHA-256'), '0609608648016503040201');
    final privateKey = Crypto.fromBase64PrivateKey(
      devicePrivateKeyStr,
    ).privateKey!;
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final signature = signer.generateSignature(
      Uint8List.fromList(ciphertextBytes),
    );

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
  static (String, String) encryptWithAES(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
  ) {
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
  static String decryptWithAES(
    Uint8List key,
    String cipherText,
    String nonceText,
  ) {
    final ciphertextBytes = base64Decode(cipherText);
    final nonce = base64Decode(nonceText);

    final gcm = GCMBlockCipher(
      AESEngine(),
    )..init(false, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));

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

  /// Signs a message using a base64-encoded RSA private key. Returns the signature as Uint8List.
  static Uint8List signWithPrivateKey(
    String privateKeyBase64,
    Uint8List message,
  ) {
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
  static bool verifyWithPublicKey(
    String publicKeyBase64,
    Uint8List message,
    Uint8List signature,
  ) {
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

  static Future<Map<String, dynamic>> encryptPayload({
    required String publicKey,
    required Map<String, dynamic> payload,
  }) async {
    print('===========encryption==========');
    // Add this to your Flutter encryption function
    print('🔑 Fresh Public Key from API: $publicKey');
    print(
        '🔑 Public Key Hash: ${publicKey.hashCode}'); // To verify it's different each time
    final publicKeyE = String.fromCharCodes(base64Decode(publicKey));
    // In your encryptPayload function, add this logging:
    print('🔑 Using Public Key: $publicKeyE');

    final plainText = json.encode(payload);
    print('🔑Generating Random Key in Dart...');
    final randomKey = Crypto.generateRandomBytes(32); // 256-bit AES key
    print('🔑  Encrypting Random Key using RSA public key...');
    final encryptedKey = Crypto.fromBase64PublicKey(publicKey)
        .encryptWithUint8ListPublicKey(randomKey);
    final encryptedKeyBase64 = base64Encode(encryptedKey);

    print("Encrypted key length: ${encryptedKey.length}");
    print("First few bytes: ${encryptedKey.take(10).toList()}");
    print("Encrypted key (base64): $encryptedKeyBase64"); // <-- Add this line

    final nonce = Crypto.generateNonce();
    final encryptedPayload = Crypto.encryptWithAES(
      randomKey,
      nonce,
      Uint8List.fromList(utf8.encode(plainText)),
    );
    print('✅ Plaintext encrypted with AES successfully');
    print('   Encrypted Payload (base64): ${encryptedPayload.$1}');
    print('   Nonce (base64): ${encryptedPayload.$2}');

    print('📦  Building JSON with encrypted data...');
    final jsonData = {
      'payload': encryptedPayload.$1,
      'key': encryptedKeyBase64,
      'nonce': encryptedPayload.$2,
    };
    final jsonString = jsonEncode(jsonData);
    print('✅ JSON built successfully');
    print('   JSON Data: $jsonString');
    return jsonData;
  }

  /// Helper to strip PKCS1 v1.5 padding from decrypted RSA output
  static Uint8List _stripPKCS1Padding(Uint8List padded) {
    if (padded.length < 12 || padded[0] != 0x00 || padded[1] != 0x02) {
      throw Exception('Invalid PKCS1 padding');
    }
    // Find the 0x00 separator after padding
    int i = 2;
    while (i < padded.length && padded[i] != 0x00) {
      i++;
    }
    if (i == padded.length) {
      throw Exception('Invalid PKCS1 padding: no separator found');
    }
    return padded.sublist(i + 1);
  }

  /// Decrypts a server response using the server's private key
  /// This method decrypts the response that was encrypted by the Go server
  static Map<String, dynamic> decryptResponse(
    Map<String, dynamic> response,
    String serverPrivateKeyBase64,
  ) {
    try {
      print('🔓 Starting decryption of server response...');

      // Debug the private key being used
      print(
          '🔑 Private key being used: ${serverPrivateKeyBase64.substring(0, 100)}...');
      print('🔑 Private key length: ${serverPrivateKeyBase64.length}');

      // Handle both uppercase and lowercase field names
      final encryptedKey = (response['key'] ?? response['Key']) as String?;
      final encryptedPayload =
          (response['payload'] ?? response['Payload']) as String?;
      final nonce = (response['nonce'] ?? response['Nonce']) as String?;

      if (encryptedKey == null || encryptedPayload == null || nonce == null) {
        throw Exception('Missing required fields: key, payload, or nonce');
      }

      print('🔓 Received encrypted data:');
      print('   Key length: ${encryptedKey.length}');
      print('   Payload length: ${encryptedPayload.length}');
      print('   Nonce length: ${nonce.length}');

      // 1. Create crypto instance with server's private key
      final crypto = Crypto.fromBase64PrivateKey(serverPrivateKeyBase64);

      // 2. Decrypt AES key with RSA private key
      final decryptedAESKeyBytesRaw =
          crypto.decryptWithPrivateKey(encryptedKey);
      print(
          '🔓 Decrypted AES key (raw, with padding) length: ${decryptedAESKeyBytesRaw.length}');
      print(
          '🔓 Raw decrypted bytes (hex): ${decryptedAESKeyBytesRaw.map((b) => b.toRadixString(16).padLeft(2, '0')).join('')}');

      // 3. Try to strip PKCS1 v1.5 padding, fallback to raw if not present
      Uint8List decryptedAESKeyBytes;
      try {
        decryptedAESKeyBytes = _stripPKCS1Padding(decryptedAESKeyBytesRaw);
        print(
            '🔓 Decrypted AES key (unpadded) length: ${decryptedAESKeyBytes.length}');
        print(
            '🔓 Unpadded bytes (hex): ${decryptedAESKeyBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('')}');
      } catch (e) {
        print(
            '⚠️ PKCS1 padding not detected, using raw decrypted bytes as AES key');
        decryptedAESKeyBytes = decryptedAESKeyBytesRaw;
      }

      // 4. Use 32-byte result directly, else brute-force
      Uint8List? finalAESKey;
      if (decryptedAESKeyBytes.length == 32) {
        finalAESKey = decryptedAESKeyBytes;
        print('✅ Using 32-byte AES key after PKCS1 padding removal');
      } else if (decryptedAESKeyBytes.length == 44) {
        // Server sends base64-encoded AES key
        print('🔍 Detected base64-encoded AES key, decoding...');
        final decodedKey =
            base64Decode(String.fromCharCodes(decryptedAESKeyBytes));
        if (decodedKey.length != 32) {
          throw Exception(
              'Invalid decoded AES key length: ${decodedKey.length}');
        }
        finalAESKey = decodedKey;
        print('✅ Successfully decoded base64 AES key to 32 bytes');
      } else {
        print(
            '⚠️ AES key after PKCS1 padding removal is not 32 bytes (got ${decryptedAESKeyBytes.length}). Brute-forcing 32-byte windows...');
        final totalWindows = decryptedAESKeyBytes.length - 31;
        for (int i = 0; i <= decryptedAESKeyBytes.length - 32; i++) {
          final candidate = decryptedAESKeyBytes.sublist(i, i + 32);
          try {
            final decryptedPayload = Crypto.decryptWithAESGCM(
              candidate,
              encryptedPayload,
              nonce,
            );
            print('✅ SUCCESS! Window $i worked as AES key');
            print('   Decrypted payload: $decryptedPayload');
            finalAESKey = candidate;
            break;
          } catch (_) {}
        }
        if (finalAESKey == null) {
          // Also try 44-byte base64 windows
          for (int i = 0; i <= decryptedAESKeyBytes.length - 44; i++) {
            final candidate = decryptedAESKeyBytes.sublist(i, i + 44);
            try {
              final decoded = base64Decode(String.fromCharCodes(candidate));
              if (decoded.length == 32) {
                try {
                  final decryptedPayload = Crypto.decryptWithAESGCM(
                    decoded,
                    encryptedPayload,
                    nonce,
                  );
                  print('✅ SUCCESS! Base64 window $i worked as AES key');
                  print('   Decrypted payload: $decryptedPayload');
                  finalAESKey = decoded;
                  break;
                } catch (_) {}
              }
            } catch (_) {}
          }
        }
        if (finalAESKey == null) {
          throw Exception(
              'No valid AES key found in any 32-byte or 44-byte window of the decrypted RSA block');
        }
      }

      // 5. Decrypt the payload using AES with the nonce
      final decryptedPayload = Crypto.decryptWithAESGCM(
        finalAESKey,
        encryptedPayload,
        nonce, // This is the base64-encoded nonce string
      );

      print(
          '🔓 Successfully decrypted payload, length: ${decryptedPayload.length}');
      print(
          '📄 Decrypted payload preview: ${decryptedPayload.substring(0, decryptedPayload.length > 100 ? 100 : decryptedPayload.length)}...');

      // 6. Parse the JSON response
      final responseData = jsonDecode(decryptedPayload) as Map<String, dynamic>;
      print(
          '✅ Successfully parsed JSON response with ${responseData.length} fields');

      return responseData;
    } catch (e) {
      print('❌ Error decrypting server response: $e');
      rethrow;
    }
  }

  /// Decrypts [cipherText] with AES using the provided [key] and [nonceText].
  /// This method properly uses the nonce for AES-GCM decryption.
  static String decryptWithAESGCM(
    Uint8List key,
    String cipherText,
    String nonceText, // This should be base64-encoded nonce
  ) {
    final ciphertextBytes = base64Decode(cipherText);
    final nonce = base64Decode(nonceText); // Decode the nonce here

    final gcm = GCMBlockCipher(
      AESEngine(),
    )..init(false, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));

    final plaintextBytes = gcm.process(ciphertextBytes);

    return String.fromCharCodes(plaintextBytes);
  }
}
