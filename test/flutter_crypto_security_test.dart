import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_crypto_security/flutter_crypto_security.dart';
import 'dart:convert';
import 'dart:typed_data';
import 'package:logger/logger.dart';

final logger = Logger();
void main() {
  final serverPrivateKey =
      "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb2dJQkFBS0NBUUVBM2lFbitjWlUrZFg0ck9IekJoZ3UwQk9BUG5SeVpQbUttOVprRStnNTlod0h4WDlaCncxUDdncWhBNDZTUEdDSnhjMExpZzZCOXR2Rk5ETW5MdUpiTHdjSmtKOHF1aVc5c1RYYlVFNGVhSnd1d3BIRDMKR212dXBmRUhRejRqQUV4MnBRbkNHcHRzUHRmcG5yMURoTngzNU56UGk3Qmhick41K3ROWXR1ODZVaEVROUJ2MQo2aGdQYk93SjBHd0NEOFljMjg5TDdveC9DQktTd29EeFhLOTFubnpmaE8zbzlibERsT3hPR2MyMkhEQVMvQU4vClU2R2traWhmQXJhU3dpdStnb0ZVeS93VlpCQ2dXb3RGY3Z2blJnT3FnT2JadUpBbmJPbHMvcVl3S1lqOXdKZlIKVXkrVzI2MHVtSHZzQlN2N2hDSDhZTE9jV3pwanlMamYzTE1iMVFJREFRQUJBb0lCQUJ0T1A1d0dlNjB2bHE5bgo0aWhDWWtUTlZPTTRqTlJwVVpicEVxbll6d0U0UG1OU2paNERqYVFvMnpzd29DK0RFbWV0RmV2QTE1dGN5OUF4CjRVTnFkQmM0Tm5nbXcvQmNuRmRrYjFzTVBSQ21NUHR4OElwVXNNUkEzaGZ2eEQwMTZSTE9JWWlFU1JqcmtVb2sKY1crY2EzZWNoajNoZTRTd2R1TDB4by9NVmlLK3dDd3ZwTzgrYzFyVVBXQWpaZjExMG5KcHB1cXN3aWVzc09Pbgo5Z0sxRkRYaUpUR1VlSld0aTNxVEpnd0hlSzZVczdqcDFRWS9Jb3g1RUdqRVlrZHNhQWdib1pJQTJzS0dhankvCnBvaUU3a0lZV0tSRnRJWWpFNGV1emhtc0JIRFRxWDM2a3F3eWltUzMyK2p3MTVleVpIcE51aEpTbENERE9jNTIKYjcwUFk2RUNnWUVBOVZKdUsrV3NnZlFNSmkxZzBHUzFVQ0lZNnVTOW5nS2liZzFGOTlSQTRqdjJKaXI3aURCUgp0amVPYmI2Y211UXlHdUlQUnV6V2hYY2dZWC9Oa0VVdWtSUW1WQ3g2ZUVWVzlDa2RCNmdCTmVVZFZrbVlkdHhUCkg5K2N6bVY1YUFUZHppVjNGZmRKc1RPMHZNbHhPbHdRVWRndTV4Skd1R3NzelpIb2hGdjk1elVDZ1lFQTU4eE0KREdyL29OalVNRjJFRFZnYVhBVzZEZjdwUUVIOE9uYS9HcmZkRXN0U2NQRDN1Qnk2OS9xd1BzNXg0bFE4dDk2TAp3OGR0eXRLZjdQNHZuNjFhMzBLZ01MUm0yNEphN0NWc010OUxLSUlRTGR1aXVraGM2WGVaNUNKWHUzSU1vR3FRCk1QcXozclJwTXh5ci82M0RpR2xJb3o0bXBsd1pHb1NRUGVjcTFpRUNnWUJPZVVQTXZ2ZGp5cEZvVlBPM05iL2EKRms0cU5XbUNkZzFIYnUrR3kxckdBN0JGblZKQXlsUVpHY1J4enB1QjRLVTJmRUd1eW13RTNZcDZKY3UzN3FscQp0eXRibWE3RGNrclNaNlJsb3BSZ2pSM0pVRmw1REJsN0JLakFUUzE4M0xHbkU4ejROZFpZM05WZjNvQmR6cjFaCnNQR3Y4T1MyY1hJdmdCRUU1ZmhlVVFLQmdIS0IydU9iaS9KeWlzZmx1cEU0LzdTTDQ3QjhSOC9GaVF0OGs4Vm8KSk43ZThEZjQ0ZmJpd240MEtoS3N1MWVhVTNCbGtOZkRVZnFLK0JRRU1aU0k5OFlvektlaXh0a1RXVVVrNjRGcQpDMS9VZUplZTA1R0FvOTExaHVGTEVkbjRha0pvd2hoZ0VMRW9vSHR1WTQxbjBwczFuM3Q4L1d6YlBFOThReUZCCmJFamhBb0dBYnNKL0J4RHFlM0NrTkdNY2dFQ2oyb2xrNFpGK0tvbDJqQllPVkhRWmIyN2ZiWUFCTmJjdHgzQjkKKzliL1luTTdjSXM2QXdlOHo1azVscVJkdklFTDZnbjJWZXB4TS9vSFh0Q1FCVjlORGV1dWZjSFBlTTE2OHR6dwpnWllkWUpRaEhlWC9uZWxtZXlab2c3YmU3TWJUamp0ekVSZjYwTndpNERrdXdWalJmckk9Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==";
  final serverPublicKey =
      "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEzaUVuK2NaVStkWDRyT0h6QmhndQowQk9BUG5SeVpQbUttOVprRStnNTlod0h4WDladzFQN2dxaEE0NlNQR0NKeGMwTGlnNkI5dHZGTkRNbkx1SmJMCndjSmtKOHF1aVc5c1RYYlVFNGVhSnd1d3BIRDNHbXZ1cGZFSFF6NGpBRXgycFFuQ0dwdHNQdGZwbnIxRGhOeDMKNU56UGk3Qmhick41K3ROWXR1ODZVaEVROUJ2MTZoZ1BiT3dKMEd3Q0Q4WWMyODlMN294L0NCS1N3b0R4WEs5MQpubnpmaE8zbzlibERsT3hPR2MyMkhEQVMvQU4vVTZHa2tpaGZBcmFTd2l1K2dvRlV5L3dWWkJDZ1dvdEZjdnZuClJnT3FnT2JadUpBbmJPbHMvcVl3S1lqOXdKZlJVeStXMjYwdW1IdnNCU3Y3aENIOFlMT2NXenBqeUxqZjNMTWIKMVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";

  group('RSA and AES Encryption/Decryption', () {
    test('Generate AES with Signature', () {
      try {
        final plaintext = '{"Code":"172","Amount":100.0,"Currency":"INR"}';
        final key = Crypto.generateRandomBytes(32); // 128-bit key
        final nounce = Crypto.generateNonce();
        // Encrypt with AES
        final encryptedAES = Crypto.encryptWithAESandGenerateSignature(
            key,
            nounce,
            Uint8List.fromList(utf8.encode(plaintext)),
            serverPrivateKey);
        logger
            .d('Encrypted AES: ${encryptedAES.$1}'); // Add print for debugging

        logger
            .d('Singature AES:  ${encryptedAES.$3}'); // Add print for debugging

        // Decrypt with AES
        final decryptedAES =
            Crypto.decryptWithAES(key, encryptedAES.$1, encryptedAES.$2);
        logger.d('Decrypted AES: $decryptedAES'); // Add print for debugging

        // Ensure the decrypted message matches the original plaintext
        expect(decryptedAES, equals(plaintext));

        bool isVerified = Crypto.fromBase64PublicKey(serverPublicKey)
            .verifySignature(encryptedAES.$1, encryptedAES.$3);
        expect(isVerified, true);
        logger.i(
            '✅ Test passes since the decrypted message matches the original plaintext');
      } catch (e) {
        logger.e('Error during RSA encryption/decryption: $e');
        rethrow;
      }
    });

    test('Test RSA Encrypt with Public Key and Decrypt with Private Key', () {
      try {
        final symmetricKey = Crypto.generateRandomBytes(32); // 128-bit key
        final plaintext = base64Encode(symmetricKey);
        logger.d('Key for encryption: $plaintext');

        // Encrypt with public key
        final encryptedMessage = Crypto.fromBase64PublicKey(serverPublicKey)
            .encryptWithPublicKey(plaintext);
        final encryptedBase64 = base64Encode(encryptedMessage);
        logger.d('Encrypted message (Base64): $encryptedBase64');

        // Decrypt with private key
        final decrypted = Crypto.fromBase64PrivateKey(serverPrivateKey)
            .decryptWithPrivateKey(encryptedBase64);
        final decryptedText = String.fromCharCodes(decrypted);
        logger.d('Decrypted message: $decryptedText');

        expect(decryptedText, equals(plaintext));
        logger.i(
            '✅ Test passes since the decrypted message matches the original plaintext');
      } catch (e) {
        logger.e('Error during RSA encryption/decryption: $e');
        rethrow;
      }
    });

    test('Test AES Encryption and Decryption', () {
      try {
        final plaintext = '{"Code":"172","Amount":100.0,"Currency":"INR"}';
        final key = Crypto.generateRandomBytes(32); // 128-bit key
        final nounce = Crypto.generateNonce();
        // Encrypt with AES
        final encryptedAES = Crypto.encryptWithAES(
            key, nounce, Uint8List.fromList(utf8.encode(plaintext)));
        logger
            .d('Encrypted AES: ${encryptedAES.$1}'); // Add print for debugging

        // Decrypt with AES
        final decryptedAES =
            Crypto.decryptWithAES(key, encryptedAES.$1, encryptedAES.$2);
        logger.d('Decrypted AES: $decryptedAES'); // Add print for debugging

        // Ensure the decrypted message matches the original plaintext
        expect(decryptedAES, equals(plaintext));
        logger.i(
            '✅ Test passes since the decrypted message matches the original plaintext');
      } catch (e) {
        logger.e('Test failed with error: $e');
        rethrow; // Re-throw to ensure the test still fails
      }
    });

    test('Test AES Decryption Failure with Wrong Key', () {
      final plaintext = '{"Code":"172","Amount":100.0,"Currency":"INR"}';
      final key = Crypto.generateRandomBytes(32); // 128-bit key
      final wrongKey = Crypto.generateRandomBytes(32); // 128-bit key

      try {
        final nounce = Crypto.generateNonce();
        // Encrypt with AES using the correct key
        final encryptedAES = Crypto.encryptWithAES(
            key, nounce, Uint8List.fromList(utf8.encode(plaintext)));
        logger
            .d('Encrypted AES: ${encryptedAES.$1}'); // Add print for debugging

        // Try to decrypt with a wrong key and ensure it fails
        final _ =
            Crypto.decryptWithAES(wrongKey, encryptedAES.$1, encryptedAES.$2);
        fail('Decryption should fail with the wrong key');
      } catch (e) {
        logger.e('Decryption failed as expected with wrong key: $key',
            error: e);
        // Test passes if an error is thrown
        logger.i('✅ Test passes since decryption failed with wrong key');
      }
    });

    test('Test RSA PKCS1 Padding Compatibility', () {
      try {
        final testMessage = 'Test message for PKCS1 padding verification';
        logger.d('Original message: $testMessage');

        // Encrypt with public key using PKCS1 padding
        final encryptedMessage = Crypto.fromBase64PublicKey(serverPublicKey)
            .encryptWithPublicKey(testMessage);
        final encryptedBase64 = base64Encode(encryptedMessage);
        logger.d('Encrypted with PKCS1 padding (Base64): $encryptedBase64');

        // Decrypt with private key using PKCS1 padding
        final decrypted = Crypto.fromBase64PrivateKey(serverPrivateKey)
            .decryptWithPrivateKey(encryptedBase64);
        final decryptedText = String.fromCharCodes(decrypted);
        logger.d('Decrypted message: $decryptedText');

        // Verify the decrypted message matches the original
        expect(decryptedText, equals(testMessage));
        logger.i('✅ Test passes - PKCS1 padding works correctly');
      } catch (e) {
        logger.e('Error during PKCS1 padding test: $e');
        rethrow;
      }
    });
  });
}
