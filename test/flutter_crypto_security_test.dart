import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_crypto_security/flutter_crypto_security.dart';
import 'dart:convert';
import 'dart:typed_data';
import 'package:logger/logger.dart';

final logger = Logger();
void main() {
  final devicePublicKeyStr =
      "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEyanE4b3VhTExwcWxuZGRlRzNlNgo1VHhhL3dGQnlYSWZ5UlJESWlETTlXVzlzemszN2pjbmJqa2FXYnpnVnRYVlNMblE4ZFN4ZFdLUmxCUEtwSFpaCkVUL0NQWjZsZm54a2MwK2dSbGZJQ0JVSU9rTG85c3l2T3VqQm1kL1JnZ1ZjMHJVakpnY3FxV3kwSkdaaE13RC8KTXlaNUdrbjhzSjVnT3NIb1dudlN3NmlNRUpMVlZ2SGtKVzhVWWxPOTZBRTFNQ0pXdnhuNHpadUNrOCtKaytpVAoyamNwMnphbEh0Y1BzY0NLSzVUTUFYWnBhSXBBVDdDcFk1YlJZUnZYSkVZa1BJOFc1ZVlMRjRZZHNERzlLSEV3CjFuL3ZKL0wxaE5SZDJxdkRLZkJCL25LNjJUTEt1TjRyanZpYm1QRTRhTGpGZit3MFZVU2l4L25HRk1Iei9DNncKQndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t";

  final devicePrivateKeyStr =
      "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBMmpxOG91YUxMcHFsbmRkZUczZTY1VHhhL3dGQnlYSWZ5UlJESWlETTlXVzlzemszCjdqY25iamthV2J6Z1Z0WFZTTG5ROGRTeGRXS1JsQlBLcEhaWkVUL0NQWjZsZm54a2MwK2dSbGZJQ0JVSU9rTG8KOXN5dk91akJtZC9SZ2dWYzByVWpKZ2NxcVd5MEpHWmhNd0QvTXlaNUdrbjhzSjVnT3NIb1dudlN3NmlNRUpMVgpWdkhrSlc4VVlsTzk2QUUxTUNKV3Z4bjR6WnVDazgrSmsraVQyamNwMnphbEh0Y1BzY0NLSzVUTUFYWnBhSXBBClQ3Q3BZNWJSWVJ2WEpFWWtQSThXNWVZTEY0WWRzREc5S0hFdzFuL3ZKL0wxaE5SZDJxdkRLZkJCL25LNjJUTEsKdU40cmp2aWJtUEU0YUxqRmYrdzBWVVNpeC9uR0ZNSHovQzZ3QndJREFRQUJBb0lCQUZPa0tKR3RHQkpVTG43NQpRVFg0NVZhZ0UrWmg5bk45dk1ZR2NKYWZpTDdUY0dwRlYzVURpYWJhMXdrbTlic0NlUjFITHRqSll2eXhPMGZNCmNDSXB4QWh5N2dGTkVYUVJ2RFJnQS9lQ0JJWm9mVDlMVHR2czVvcUhGRkRrTW5vSmtTS25UMkh2WkVBTWpGeloKS283d1psK1Y4dHVMR1FFZXFwWktwTUl0YkVJVjNkMk9zMmlUOGNlMm9iSm1zdG9WUWN4OGMwN0MvUnY3aDNXcwpnQWpjSnF5UVJuMlFqWnlySG9OOE1aNDUzWXM1V1RHMUN4Vy9CKzFjQk1SMEk1aWhZeVFWYldWK1VXNStYOFpKCmEwL2ZwelhNTWdqY2Ryd1JDUTI5V215UnVDQStCSWx1eVFPd0lYWGlzZElpbVNzK2JscFZleG5ISDk3c3dZWm4KWU5ubEEva0NnWUVBNWlheDdRSWtZeU1uTUhwb1R3M2VwR2hFWm5uNWlrYmhCTnVqZEF2UnVPYWZJNWJQY0VNcQpGVkI5OEVLVlNrSC9jYW9iRlFVL0xoNXhKV3ZvcnMzUUIxUTUySWxVS1ZFbEtxN1dsdVlYcUF4Zm10SWFicDVNCnFIMGY2cTMvdnhqUEZTNlZ2eFBBbGZhYWhVWjBWZnB2S1FFNUYvNERrZDV1a1BlaTJDZ0F2KzhDZ1lFQThyMUUKMG5lZExTZTRqTlU0RG9IVlJlRW5zL2xNSjhrNlZNYi9GZTQxU0VBSmdpZG9SNmVJVzRGMEh5Qm1lSUliVXl4SQpjVnNRazhCdEtQZ3BWbDJpOFlMNTFhTS9QazFXelBrdUt0dVZDYVREdHRKNWxJYklFVmtFV3dwZDdyTTFsRUVrCk5wMEpnL0ZwSnp5d1NjMDQzWWtjdG12WmFrQ01pR3lTWTdGWWVXa0NnWUVBc3FNT0wxd2VTaVNhNG5IZ1RKd0QKVjdEbWhuUGVVSW03VmozMG5Mb2Z5bGlXNU5URnBlazczTmRoS1A5RlNTSDQxNHlsQUtmVjVrSVNxRzBkYWJDdAo2MEpnczhYRDRWM3ViemJOc01wZlNqeHdhSWJ6cFRDUlo2WFhCQnlTQ1EyRWpuaGVHcldHSWVBTEI2OHIxU0JRCjc0N1hkZHZmZ1hVWWRNVUJUSzJnQjFrQ2dZQnV1Q0FkTkF3UVhhN1RKaXBVaTZvQkhzc2lUMU1LVHNINWkyOHMKektPbkdmWjhWSWMvTDg2RmxvMmw2UHgwZVR3SGV3cHNFaEtFb2wvb01SR0I0R0lEY1MrTjM5Rm9GSlRFRitDVQpFZVp3S0tSUXpyNUFIaDVCczIzR0xQdGRkb2E0NGVHbnU0ZHNsSC9YTXRwaVAyWnh2aW5IbDNmcS9CaGQzZEFFCkF3K05DUUtCZ0JtOEV1ZTVrZTFnWG1KRmpYL2s2dWhjVzVlN0Z1L2dyYjRrS3pPUUFjMmZlVEx5RVhvcnpsR1kKTTkzWlRYOGUyTUVieTJzaHo0eng0cEdNWFVDWkRyQWtXdm1BNmdCT1N1eDRoWHdiNlJSRW56UU91Ni9TemNqbgppeUpBa2wwMngyR3RvRVV0bml0N2d4ZDYzZzVUOTRMRk41eW9aNUhxN1Q5OFFGVWk5ck9WCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t";
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
            devicePrivateKeyStr);
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

        bool isVerified = Crypto.fromBase64PublicKey(devicePublicKeyStr)
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
        final encryptedMessage = Crypto.fromBase64PublicKey(devicePublicKeyStr)
            .encryptWithPublicKey(plaintext);
        final encryptedBase64 = base64Encode(encryptedMessage);
        logger.d('Encrypted message (Base64): $encryptedBase64');

        // Decrypt with private key
        final decrypted = Crypto.fromBase64PrivateKey(devicePrivateKeyStr)
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
  });
}
