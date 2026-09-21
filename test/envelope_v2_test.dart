import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_crypto_security/flutter_crypto_security.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List utf8Bytes(String s) => Uint8List.fromList(utf8.encode(s));

String flip(String b64) {
  final raw = base64Decode(b64);
  raw[0] ^= 1;
  return base64Encode(raw);
}

void main() {
  group('Envelope v2', () {
    test('keys are base64 of 32 raw bytes', () async {
      final (xPriv, xPub) = await CryptoV2.generateX25519KeyPair();
      final (edPriv, edPub) = await CryptoV2.generateEd25519KeyPair();
      for (final k in [xPriv, xPub, edPriv, edPub]) {
        expect(base64Decode(k).length, 32);
      }
    });

    test('Ed25519 sign / verify', () async {
      final (edPriv, edPub) = await CryptoV2.generateEd25519KeyPair();
      final (_, otherPub) = await CryptoV2.generateEd25519KeyPair();
      final msg = utf8Bytes('sign me');
      final sig = await CryptoV2.signEd25519(edPriv, msg);
      expect(base64Decode(sig).length, 64);
      expect(await CryptoV2.verifyEd25519(edPub, msg, sig), isTrue);
      expect(await CryptoV2.verifyEd25519(edPub, utf8Bytes('sign me!'), sig),
          isFalse);
      expect(await CryptoV2.verifyEd25519(otherPub, msg, sig), isFalse);
      expect(await CryptoV2.verifyEd25519(edPub, msg, 'AAAA'), isFalse);
    });

    test('round trip, JSON shape, fresh ephemeral key', () async {
      final (xPriv, xPub) = await CryptoV2.generateX25519KeyPair();
      final payload = utf8Bytes('{"hello":"v2"}');
      final env = await CryptoV2.encryptEnvelope(
          recipientX25519PublicKey: xPub, payload: payload);
      expect(env['v'], 2);
      expect(env.keys, containsAll(['epk', 'nonce', 'payload']));
      expect(env.containsKey('signature'), isFalse);
      expect(base64Decode(env['epk'] as String).length, 32);

      expect(
          await CryptoV2.decryptEnvelope(
              recipientX25519PrivateKey: xPriv, envelope: env),
          equals(payload));
      final env2 = await CryptoV2.encryptEnvelope(
          recipientX25519PublicKey: xPub, payload: payload);
      expect(env2['epk'], isNot(equals(env['epk'])));

      final json = await CryptoV2.encryptPayload(
          recipientX25519PublicKey: xPub, payload: {'a': 1});
      expect(await CryptoV2.decryptResponse(json, xPriv), equals({'a': 1}));
    });

    test('signed envelope verifies and rejects tampering', () async {
      final (sPriv, sPub) = await CryptoV2.generateX25519KeyPair();
      final (dPriv, dPub) = await CryptoV2.generateEd25519KeyPair();
      final (_, strangerPub) = await CryptoV2.generateEd25519KeyPair();
      final (oPriv, _) = await CryptoV2.generateX25519KeyPair();
      final payload = utf8Bytes('signed v2');

      final env = await CryptoV2.encryptEnvelope(
          recipientX25519PublicKey: sPub,
          payload: payload,
          senderEd25519PrivateKey: dPriv);
      expect(
          await CryptoV2.decryptEnvelope(
              recipientX25519PrivateKey: sPriv,
              envelope: env,
              senderEd25519PublicKey: dPub),
          equals(payload));

      Future<Uint8List> open(Map<String, dynamic> e, {String? sender = ''}) =>
          CryptoV2.decryptEnvelope(
              recipientX25519PrivateKey: sPriv,
              envelope: e,
              senderEd25519PublicKey: sender == '' ? dPub : sender);

      expect(() => open(env, sender: strangerPub), throwsStateError);
      expect(
          () => CryptoV2.decryptEnvelope(
              recipientX25519PrivateKey: oPriv,
              envelope: env,
              senderEd25519PublicKey: dPub),
          throwsA(anything));

      for (final field in ['payload', 'nonce', 'epk']) {
        final t = Map<String, dynamic>.from(env);
        t[field] = flip(t[field] as String);
        expect(() => open(t), throwsStateError, reason: field);
      }
      final tampered = Map<String, dynamic>.from(env);
      tampered['payload'] = flip(tampered['payload'] as String);
      expect(() => open(tampered, sender: null), throwsA(anything));

      final unsigned = Map<String, dynamic>.from(env)..remove('signature');
      expect(() => open(unsigned), throwsArgumentError);
      expect(await open(unsigned, sender: null), equals(payload));

      final wrongVersion = Map<String, dynamic>.from(env)..['v'] = 1;
      expect(() => open(wrongVersion, sender: null), throwsArgumentError);
      expect(
          () => open({'v': 2, 'epk': 'x'}, sender: null), throwsArgumentError);
    });
  });
}
