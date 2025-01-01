# flutter_crypto_security

A Flutter package for encryption and decryption of data using RSA and AES algorithms, with built-in signature verification. It provides utilities for secure communication and data protection.

## Features

- **AES Encryption/Decryption:** Encrypt and decrypt data with AES, including signature generation and verification.
- **RSA Encryption/Decryption:** Encrypt and decrypt AES keys using RSA public and private keys.
- **Signature Verification:** Verify data integrity using RSA signatures.
- **Logging and Debugging:** Includes detailed logs to help you track encryption and decryption processes.

Here's an updated **Installation** section for your `README.md` based on the package location:

## Installation

To use `flutter_crypto_security` in your Flutter project, follow these steps:

1. Add the following dependency in your `pubspec.yaml` file:

   ```yaml
   dependencies:
     flutter_crypto_security:
       git:
         url: https://github.com/sudhi001/flutter_crypto_security.git
   ```

2. Install the package by running:

   ```bash
   flutter pub get
   ```

3. You can now use the package in your Flutter project by importing it:

   ```dart
   import 'package:flutter_crypto_security/flutter_crypto_security.dart';
   ```

For more information on how to use the package, check the [example](https://github.com/sudhi001/flutter_crypto_security/tree/main/example).

## Usage

This package supports both **AES** and **RSA** encryption. Below are examples demonstrating how to use each feature.

### AES Encryption and Decryption

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_crypto_security/flutter_crypto_security.dart';
import 'package:logger/logger.dart';

final logger = Logger();

void main() {
  final plaintext = '{"Code":"172","Amount":100.0,"Currency":"INR"}';
  final key = Crypto.generateRandomBytes(32); // 128-bit key
  final nonce = Crypto.generateNonce();
  
  // Encrypt with AES
  final encryptedAES = Crypto.encryptWithAES(key, nonce, Uint8List.fromList(utf8.encode(plaintext)));
  logger.d('Encrypted AES: ${encryptedAES.$1}'); // Debug log for encrypted data

  // Decrypt with AES
  final decryptedAES = Crypto.decryptWithAES(key, encryptedAES.$1, encryptedAES.$2);
  logger.d('Decrypted AES: $decryptedAES'); // Debug log for decrypted data

  // Ensure the decrypted message matches the original plaintext
  assert(decryptedAES == plaintext);
}
```

### AES Encryption with Signature

```dart
void main() {
  final plaintext = '{"Code":"172","Amount":100.0,"Currency":"INR"}';
  final key = Crypto.generateRandomBytes(32); // 128-bit key
  final nonce = Crypto.generateNonce();
  final devicePrivateKeyStr = "YOUR_PRIVATE_KEY_HERE"; // Replace with your private key
  
  // Encrypt with AES and generate signature
  final encryptedAES = Crypto.encryptWithAESandGenerateSignature(
    key,
    nonce,
    Uint8List.fromList(utf8.encode(plaintext)),
    devicePrivateKeyStr,
  );
  logger.d('Encrypted AES: ${encryptedAES.$1}');
  logger.d('Signature: ${encryptedAES.$3}');

  // Decrypt with AES
  final decryptedAES = Crypto.decryptWithAES(key, encryptedAES.$1, encryptedAES.$2);
  logger.d('Decrypted AES: $decryptedAES');

  // Ensure the decrypted message matches the original plaintext
  assert(decryptedAES == plaintext);

  // Verify signature with public key
  bool isVerified = Crypto.fromBase64PublicKey("YOUR_PUBLIC_KEY_HERE") // Replace with your public key
      .verifySignature(encryptedAES.$1, encryptedAES.$3);
  assert(isVerified == true);
}
```

### RSA Encryption/Decryption

#### RSA Encryption with Public Key and Decryption with Private Key:

```dart
void main() {
  final symmetricKey = Crypto.generateRandomBytes(32); // 128-bit key
  final plaintext = base64Encode(symmetricKey);
  final devicePublicKeyStr = "YOUR_PUBLIC_KEY_HERE"; // Replace with your public key
  final devicePrivateKeyStr = "YOUR_PRIVATE_KEY_HERE"; // Replace with your private key
  
  // Encrypt with public key
  final encryptedMessage = Crypto.fromBase64PublicKey(devicePublicKeyStr)
      .encryptWithPublicKey(plaintext);
  final encryptedBase64 = base64Encode(encryptedMessage);
  logger.d('Encrypted message (Base64): $encryptedBase64');

  // Decrypt with private key
  final decrypted = Crypto.fromBase64PrivateKey(devicePrivateKeyStr)
      .decryptWithPrivateKey(encryptedBase64);
  final decryptedText = String.fromCharCodes(decrypted);
  logger.d('Decrypted message: $decryptedText');

  // Ensure the decrypted message matches the original plaintext
  assert(decryptedText == plaintext);
}
```

### Testing for AES Decryption Failure with Wrong Key:

```dart
void main() {
  final plaintext = '{"Code":"172","Amount":100.0,"Currency":"INR"}';
  final key = Crypto.generateRandomBytes(32); // 128-bit key
  final wrongKey = Crypto.generateRandomBytes(32); // 128-bit key

  try {
    final nonce = Crypto.generateNonce();
    // Encrypt with AES using the correct key
    final encryptedAES = Crypto.encryptWithAES(
        key, nonce, Uint8List.fromList(utf8.encode(plaintext)));
    logger.d('Encrypted AES: ${encryptedAES.$1}');

    // Try to decrypt with a wrong key and ensure it fails
    Crypto.decryptWithAES(wrongKey, encryptedAES.$1, encryptedAES.$2);
    throw Exception('Decryption should fail with the wrong key');
  } catch (e) {
    logger.e('Decryption failed as expected with wrong key');
  }
}
```

## Tests

This package includes tests for both **AES** and **RSA** encryption and decryption processes:

- **Test AES Encryption and Decryption:** Ensures AES encryption and decryption works with the correct key.
- **Test RSA Encryption with Public Key and Decryption with Private Key:** Verifies that RSA encryption with a public key and decryption with a private key works as expected.
- **Test AES with Signature:** Validates AES encryption with a signature and verifies the signature with the public key.
- **Test AES Decryption Failure with Wrong Key:** Ensures AES decryption fails with the wrong key.

## License

MIT License. See the [LICENSE](LICENSE) file for details.

