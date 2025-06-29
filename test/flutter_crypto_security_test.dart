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

    test('Decrypt Real Server Response', () {
      try {
        // The response data provided by the user
        final responseData = {
          'Payload':
              '/uNtQlCaHUfLnqx7ML4HbtzwDhzA+9g6p/nlTI8mFHcJDeVX3ZfZIKgs2iH6e1lAMaMcKoYnWAZfdDLMTrWj69tx6VKK9eL2bI9MfNWmgTwJZXeOWQPQreXhzvbeTlzUcPtD9jvU23Q4dzgyNwvtibC9IVp/lVKZ/ERzy6G4vZ9dmeyMosTxaC95ytfW+4HSuZC3fnT/QPB7KydfS5zwh9rUBympku2wkW4hUdBIkd6pJpsyCHe53nfZUrUVNBFVmi6gLDulGeQPiZ1FjGnDjHnyDwJ+lpbT3554sVIfFPCq3uUdW0amZEu0vyC2CT8pSi7CPOtjSgufKdKl+Mb1WcEW59U+oqvXllg1p4oyfhamyutUNq+eAvsubMCzIbpAWOP59Vm8AeJMLGYU1Y1Crk9L/oqpdJJt2MhtnWjqZil9MQwzjgx6JGmy2pOk7pgS9+w4ufHKE2lhgOTQkryzdQpbHfbTEY5hw5m//v4Qdd9pMYSTLeyvhfXExQBfdUpwUPBjKoMIi6gZEyAPWlE2oKM6g4wDyoFSzA5vOz0d6wbeHw3Kr9qNLxT1URXdZYW7mmG/iZWQt+tGtyUgyEtKgRhvXKYX3JGEfQBUnmoH83KRw6O8JHWWtmJTWmA3FCjVIKDcSvvKoTXzILhtmZ5Wvzr+KQQlR1kOPC1lOxIRYa0smmFM0r8PJAI9ovvD1NPIErxQ/mx8TWHE4U9DAPk8c9U5PC/hGoX1E6WWMeOWn7jA5BLB6+IQe4ef/AO6fvS4mWwpFARNdC5yB55TXLQi6PolKicxa2tCXd/gD/0N8e9vYGZ3LLu3sUaCGtXz4BT8aUucZRy/+5qj31sQs1S1D07HHCFCH+epKqRF0TeNycroKCACdO1ZckbzDcYMblwhadLpyy853fM0hxnerMhqhUxwX3FEue5GR1nSdmrpObnMQ6tOi2b4zFjK2x6ShttA1596Jti53rRn9ltCElM8QpvFrx5OYnBCkVQgnxMBlzgaDHpi3MrgTVTOCJSSUJDaSJ9lj+H1eKXUHVyhjy0RMXbC66d88ecwtkhWQLv9lPrEQ3vq/yITfXfh3/dpdpuxpsYEKt3m31as0y0ONtPRAQ18X9iWGMGWUibRtxATKHzPeCx1RwUOlSrwbPoh2gGpA/bj3bAUIujs0UH+O4GYS2ZYabKH9HP/0oQ4BPNjTNlios5Z8z/m41gmliR6mx0Zd24kGg4GstNG6c50QIe/J9jf9xhn9uzElrPfW/bMYwPpVFv4kiM9SAh8VGT0PDkycCUDH/yOKkO2m4OR7H8RsnbbCTFQIH4GsQFLq/MMR35IHomR9gXVE825tmwhrgw2DtURRbNHtF38LF6NoO8DjoinUFOrmbMKudBbQbobg5cVCzUPrr8OWdR5B19KrwLkuliaGh+ll//3KTdJLz7Ntlz91daE4oVtH/2kTg8Zw3hAXd/TgFW49OoRbWRPM2isooz5fECniFZOwm3/KE8DIU7gMYiXP5ZJwkfm2sH1tw==',
          'Key':
              'tvZgHRj4ICqAa1YmgW1Ht7zw1SdR2hg3BhMvdxPcFDm0/3kG4xRRT3V0B+BclqljRLKIuVBsdVOIWCjnUrMvB0aXEXZUPIMci0IeBkKFd++gdwieLKONeJMEGiuQqDuxJUvTvjVEBM2EbQ6uh1LsbT4+XhQctlITIA0TNNSAgJ3uMgyG82R/+q37ZIZxJFCZpWqjctk79YKUHih9WiPrcwEvzVGsr3utOnkrZngEqkeEAeGi5DDu5UHOT7EHPAgTAPFGg/wuiue1N/PoA/QhSPYnusC2vtiCZo69usc3tiqdsLhwLgusOOHxLg6KSZifww8jrgBZmJHxXh7/+PYB1w==',
          'Nonce': 'yok6ogjvWG24NeMD'
        };

        // Server's private key for testing
        const String serverPrivateKeyBase64 =
            "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBeTF5MDJZSHlqOENXcy9CaHlyZTFKMnBYaGlpLzVBRkdrZzNRZEltbGNWMWx2UnRtClRNUGpkWHNZYWtodi9RZUdKbzFFRUxtRWE5L1gvUm9xUzd2QWJ5S3A2SVJxYU1LQys5QUpJL1UzdjdmWTN1UzQKZEgySlFZaGh1WHVqb2xLak5HODBvd2pvK3drN1UwSy9qYVlGSWtvMjFZbTZVSFBuSVZFWHh4cTVSb2h3eFF2VApwZVlRdk1Yald0THdwKy9xQmZCOG5CK2MrSVBPVVhyeDdPdDQ2OERwU2x6T0NjR3c3azgzK1lFMTc3OElIRGJOCk5HamQyWGZwMzNMNHFVdytFSWE1U09qcllTRG5iU3E5Sk5XeGhITHgrLzAyZ0NycWFLOENoRXFZMGErTW9qWlMKSS9uS0Y3MVpMSFdsKzh6cUJOZUZEcWFSY25iRXVHYTAvSC83SlFJREFRQUJBb0lCQUV5T1ZGaXpoanhlbkgwVgp4OEs0UUw2YlZtS2ZjWW1rZjB3WlhqbVkzY3JkQmFGWXNMekNXNTBNMzRhWFNXMWdTVHkzSG9JTFROSU5YUEtmCnlIOWxLVTdOSmxodGpOOXVKa0FrczJReGVyQzJSYkszT01kRndRZUdEMy96andqYkFpeUpscSt2ZVlHVG1wMC8KK2Z1Wm5jSW9YUmNyTjVQMDVmUlJZbG1tY2t3ZUFrUDRFUEpGQXhuVGNFUHJpNE5MenEwekMrd0s4clBOSWN1bgpYWW02U2lwbC9kdlJHNkFaMC8wVDRxc244YlFCaVljY1FvMHFaNnZ5Qk9qU0JGMUFNZ3F1bm9NVTU2R0ZZNDlECkJyNHRDN1dzTDJaMDdEYzBnNndqeHZ5ZVR3UGFCdXpxMGY0ZjdySnBaTjZVeFJZRUkzM1cxN1lIVlZjb0d1VFoKTS9tSmdyc0NnWUVBNXd5Z0dFaFJzRWRrSnlmU0NuQ0VjVFVNZE1VVVB5b1M0NG4ySHNGMnd4Vkp2cGZKUUttcgo1Rm8wMlZLdXI2LzAxZWtJZy9VVHNCdlROcTk5azlSM0dDTnJYbllZZlA0cVdlR3JkNGlMbzJndVZXZHEyQlduCnhZVW5HZFlJdVVEZE9COTVpSTZpSU9MMVpQclhwWEc0dG5sajBuNnhQKy9rRTljNGFOcGRTWThDZ1lFQTRWS3EKdk9uUHB5dDRmVkh1b3pwN2tqVHlrUTVPRXNzUXQ0MjNPeTVua2R4cmZhQ1czanNZRGhpQy9KYnVDSmVYaXlwSgpDTitSNUhHZjBHOUtsa0dlR3BJUUtYQzg0cGpqaFpoV1JRMmpNYjJURjZYRVp0bkgxNHE3RENORFd4R0kxNHN6CnRpOXo0dS9FWGE0VWU1QkVIVEcrdG5ocDlIOGc3ZW5zQW93SURnc0NnWUVBd3VSYWNzRWw3c3o1aFRISXNiZWgKY0NDd1Joc3JiZkJlaUlLS0VmMWM0VWVtc2RjMUVvOU1pRTB6QVJJR2VmbXhTM0xMRlF2NE5IZjBITS9BM0o2KwphcVVOMzFzOFlzcStESjBYMXJkZUdsTTVxaDZXK0hpajBTLzFBSTBUUkxpYklja2k2Zlp1ZWRFWDc3ckxoaW04CkJtZTB0UXpiRkxTVXJjdkFNR25wZ0s4Q2dZQms1NlZvaG5pa3ozWGRBV1VTR2kyZWt6R1J2a3MrWlV2dU4zdTMKK0JjUG5odFJIaXFTQ1ByRHpUeFRxNitiajIraE5lV1JJTFh3RE9aWjdJMEZid3REc09lbDkwUFBZbEo1MEhmSgo0c3FUaXVjbGJ1bmVlV2JpWXRGVEpUT1R3KzE1UVhCK0JSQXJyOTVMYVpyb252bXg3VVlQNXlya0FFNlozT2tCClZ2NkFjd0tCZ0JDUnZob21XaDVyeE1xa3RCdWlTekhaNStVT2d0by9LMzJNM0xPQnhrSU41WlZ4RDVsd2J4WGUKN1h3QUZuUzFCMWRkbUhaQXNGTGFObUFyb0hBVFpQcU40NzM3M1EyZXR6aGg5OExjNnRBZUM4NkYrUGVVUWUrdQpMUFBLaTc2VzNHOGhhVG5oeHlKcXhaRmZrcTd5T2E1TGRvdkx6V3JKVUtJRWV4VXZBVnFCCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==";

        logger.d('🔓 Starting decryption of real server response...');

        // Decrypt the response using the server's private key
        final decryptedData =
            Crypto.decryptResponse(responseData, serverPrivateKeyBase64);

        logger.d('✅ Successfully decrypted server response!');
        logger.d('📄 Decrypted data: $decryptedData');

        // Verify the decrypted data contains expected fields
        expect(decryptedData, isA<Map<String, dynamic>>());
        expect(decryptedData['Code'], equals('118'));
        expect(decryptedData['Name'], isA<String>());
        expect(decryptedData['Duration'], equals(12));

        logger.i('✅ Test passes - Real server response decrypted successfully');
      } catch (e) {
        logger.e('Error decrypting real server response: $e');
        rethrow;
      }
    });
  });
}
