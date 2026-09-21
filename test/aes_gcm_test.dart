import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_crypto_security/flutter_crypto_security.dart';
import 'package:flutter_test/flutter_test.dart';
import 'dart:math';
import 'package:pointycastle/export.dart';

Uint8List hex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String toHex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List pointyGcm(
    Uint8List key, Uint8List nonce, Uint8List input, bool forEncryption) {
  final gcm = GCMBlockCipher(AESEngine())
    ..init(forEncryption,
        AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
  return gcm.process(input);
}

void main() {
  group('AES-GCM NIST SP 800-38D vectors (AES-256)', () {
    test('Test Case 13: empty plaintext', () {
      final gcm = AesGcm(Uint8List(32));
      final out = gcm.encrypt(Uint8List(12), Uint8List(0));
      expect(toHex(out), '530f8afbc74536b9a963b4f1c4cb738b');
    });

    test('Test Case 14: one zero block', () {
      final gcm = AesGcm(Uint8List(32));
      final out = gcm.encrypt(Uint8List(12), Uint8List(16));
      expect(toHex(out),
          'cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919');
    });

    test('Test Case 15: four blocks', () {
      final key = hex(
          'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
      final nonce = hex('cafebabefacedbaddecaf888');
      final plaintext = hex(
          'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255');
      final out = AesGcm(key).encrypt(nonce, plaintext);
      expect(
          toHex(out),
          '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa'
          '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad'
          'b094dac5d93471bdec1a502270e3cc6c');
      expect(AesGcm(key).decrypt(nonce, out), plaintext);
    });

    test('Test Case 16: with AAD and partial block', () {
      final key = hex(
          'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
      final nonce = hex('cafebabefacedbaddecaf888');
      final plaintext =
          hex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
              '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
      final aad = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
      final out = AesGcm(key).encrypt(nonce, plaintext, aad: aad);
      expect(
          toHex(out),
          '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa'
          '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662'
          '76fc6ece0f4e1768cddf8853bb2d551b');
      expect(AesGcm(key).decrypt(nonce, out, aad: aad), plaintext);
    });
  });

  group('AES-GCM agrees with PointyCastle GCMBlockCipher', () {
    test('random keys and sizes 0..300 bytes, AES-128/192/256', () {
      final rnd = Random.secure();
      for (final keySize in [16, 24, 32]) {
        for (var len = 0; len <= 300; len += 7) {
          final key = Uint8List.fromList(
              List.generate(keySize, (_) => rnd.nextInt(256)));
          final nonce =
              Uint8List.fromList(List.generate(12, (_) => rnd.nextInt(256)));
          final plaintext =
              Uint8List.fromList(List.generate(len, (_) => rnd.nextInt(256)));

          final ours = AesGcm(key).encrypt(nonce, plaintext);
          final theirs = pointyGcm(key, nonce, plaintext, true);
          expect(ours, theirs, reason: 'encrypt keySize=$keySize len=$len');
          expect(AesGcm(key).decrypt(nonce, theirs), plaintext,
              reason: 'decrypt len=$len');
        }
      }
    });

    test('large input (70000 bytes) matches', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final nonce = Uint8List.fromList(List.generate(12, (i) => 200 - i));
      final plaintext =
          Uint8List.fromList(List.generate(70000, (i) => (i * 31) & 0xff));
      expect(AesGcm(key).encrypt(nonce, plaintext),
          pointyGcm(key, nonce, plaintext, true));
    });
  });

  group('AES-GCM failure modes', () {
    final key = Uint8List(32);
    final nonce = Uint8List(12);
    final plaintext = Uint8List.fromList(utf8.encode('authenticated data'));

    test('tampered ciphertext, tag, wrong key, wrong nonce', () {
      final out = AesGcm(key).encrypt(nonce, plaintext);

      final t1 = Uint8List.fromList(out)..[0] ^= 1;
      expect(() => AesGcm(key).decrypt(nonce, t1), throwsStateError);

      final t2 = Uint8List.fromList(out)..[out.length - 1] ^= 1;
      expect(() => AesGcm(key).decrypt(nonce, t2), throwsStateError);

      final wrongKey = Uint8List(32)..[5] = 1;
      expect(() => AesGcm(wrongKey).decrypt(nonce, out), throwsStateError);

      final wrongNonce = Uint8List(12)..[0] = 1;
      expect(() => AesGcm(key).decrypt(wrongNonce, out), throwsStateError);

      expect(
          () => AesGcm(key).decrypt(nonce, Uint8List(10)), throwsArgumentError);
      expect(() => AesGcm(key).encrypt(Uint8List(16), plaintext),
          throwsArgumentError);
    });
  });
}
