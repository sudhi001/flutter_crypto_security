// Interoperability CLI mirroring `crypto_utils/cmd/interop` (Go) and
// `cargo run --example interop` (Rust). Run with `dart run tool/interop.dart`.
//
//   keygen      <priv_out> <pub_out>
//   encrypt     <recipient_pub> <sender_priv|-> <in> <out_json> [pkcs1|oaep]
//   decrypt     <recipient_priv> <sender_pub|-> <in_json> <out> [pkcs1|oaep]
//   rsa-encrypt <pub> <in> <out_b64> [pkcs1|oaep]
//   rsa-decrypt <priv> <in_b64> <out> [pkcs1|oaep]
//   sign        <priv> <in> <out_b64>
//   verify      <pub> <in> <sig_b64>
//   aes-encrypt <key_b64_file> <in> <out_json>
//   aes-decrypt <key_b64_file> <in_json> <out>
//   keygen-v2   <x25519_priv_out> <x25519_pub_out> <ed25519_priv_out> <ed25519_pub_out>
//   encrypt-v2  <recipient_x25519_pub> <sender_ed25519_priv|-> <in> <out_json>
//   decrypt-v2  <recipient_x25519_priv> <sender_ed25519_pub|-> <in_json> <out>
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_crypto_security/flutter_crypto_security.dart';

Future<void> main(List<String> args) async {
  try {
    await run(args);
  } catch (e) {
    stderr.writeln('error: $e');
    exit(1);
  }
}

Future<void> run(List<String> args) async {
  if (args.isEmpty) {
    throw ArgumentError('missing sub-command');
  }
  final cmd = args.first;
  final a = args.sublist(1);
  bool oaep(int i) => a.length > i && a[i] == 'oaep';

  switch (cmd) {
    case 'keygen':
      need(a, 2);
      final (priv, pub) = Crypto.generateRSAKeyPair();
      File(a[0]).writeAsStringSync(priv);
      File(a[1]).writeAsStringSync(pub);

    case 'encrypt':
      need(a, 4);
      final envelope = Crypto.encryptEnvelope(
        recipientPublicKey: readKey(a[0]),
        senderPrivateKey: optionalKey(a[1]),
        payload: readBytes(a[2]),
        oaep: oaep(4),
      );
      File(a[3]).writeAsStringSync(
        const JsonEncoder.withIndent('  ').convert(envelope),
      );

    case 'decrypt':
      need(a, 4);
      final envelope =
          jsonDecode(File(a[2]).readAsStringSync()) as Map<String, dynamic>;
      final plaintext = Crypto.decryptEnvelope(
        recipientPrivateKey: readKey(a[0]),
        senderPublicKey: optionalKey(a[1]),
        envelope: envelope,
        oaep: oaep(4),
      );
      File(a[3]).writeAsBytesSync(plaintext);

    case 'rsa-encrypt':
      need(a, 3);
      final crypto = Crypto.fromBase64PublicKey(readKey(a[0]));
      final message = readBytes(a[1]);
      final encrypted = oaep(3)
          ? crypto.encryptWithPublicKeyOAEP(message)
          : crypto.encryptWithUint8ListPublicKey(message);
      File(a[2]).writeAsStringSync(base64Encode(encrypted));

    case 'rsa-decrypt':
      need(a, 3);
      final crypto = Crypto.fromBase64PrivateKey(readKey(a[0]));
      final encrypted = readKey(a[1]);
      final decrypted = oaep(3)
          ? crypto.decryptWithPrivateKeyOAEP(encrypted)
          : crypto.decryptWithPrivateKey(encrypted);
      File(a[2]).writeAsBytesSync(decrypted);

    case 'sign':
      need(a, 3);
      File(a[2]).writeAsStringSync(Crypto.sign(readKey(a[0]), readBytes(a[1])));

    case 'verify':
      need(a, 3);
      if (!Crypto.verify(readKey(a[0]), readBytes(a[1]), readKey(a[2]))) {
        throw StateError('signature verification failed');
      }

    case 'aes-encrypt':
      need(a, 3);
      final key = base64Decode(readKey(a[0]));
      final (ciphertext, nonce) =
          Crypto.encryptWithAES(key, Crypto.generateNonce(), readBytes(a[1]));
      File(a[2]).writeAsStringSync(
        const JsonEncoder.withIndent('  ')
            .convert({'ciphertext': ciphertext, 'nonce': nonce}),
      );

    case 'aes-decrypt':
      need(a, 3);
      final key = base64Decode(readKey(a[0]));
      final input =
          jsonDecode(File(a[1]).readAsStringSync()) as Map<String, dynamic>;
      final plaintext = Crypto.decryptWithAESBytes(
        key,
        base64Decode(input['nonce'] as String),
        base64Decode(input['ciphertext'] as String),
      );
      File(a[2]).writeAsBytesSync(plaintext);

    case 'keygen-v2':
      need(a, 4);
      final (xPriv, xPub) = await CryptoV2.generateX25519KeyPair();
      final (edPriv, edPub) = await CryptoV2.generateEd25519KeyPair();
      File(a[0]).writeAsStringSync(xPriv);
      File(a[1]).writeAsStringSync(xPub);
      File(a[2]).writeAsStringSync(edPriv);
      File(a[3]).writeAsStringSync(edPub);

    case 'encrypt-v2':
      need(a, 4);
      final envelope = await CryptoV2.encryptEnvelope(
        recipientX25519PublicKey: readKey(a[0]),
        senderEd25519PrivateKey: optionalKey(a[1]),
        payload: readBytes(a[2]),
      );
      File(a[3]).writeAsStringSync(
        const JsonEncoder.withIndent('  ').convert(envelope),
      );

    case 'decrypt-v2':
      need(a, 4);
      final envelope =
          jsonDecode(File(a[2]).readAsStringSync()) as Map<String, dynamic>;
      final plaintext = await CryptoV2.decryptEnvelope(
        recipientX25519PrivateKey: readKey(a[0]),
        senderEd25519PublicKey: optionalKey(a[1]),
        envelope: envelope,
      );
      File(a[3]).writeAsBytesSync(plaintext);

    default:
      throw ArgumentError('unknown sub-command "$cmd"');
  }
}

void need(List<String> a, int n) {
  if (a.length < n) {
    stderr.writeln('error: expected at least $n arguments, got ${a.length}');
    exit(2);
  }
}

Uint8List readBytes(String path) => File(path).readAsBytesSync();

String readKey(String path) => File(path).readAsStringSync().trim();

/// `-` means "no key": skip signing / signature verification.
String? optionalKey(String path) => path == '-' ? null : readKey(path);
