// Micro-benchmarks of the public API. Run with:
//
//   dart compile exe benchmark/bench.dart -o /tmp/bench && /tmp/bench   # AOT, like a Flutter release build
//   dart run benchmark/bench.dart                                        # JIT
//
// Prints one `name<TAB>ns_per_op` line per benchmark (the format consumed by
// `interop/bench.sh`). RSA numbers include base64 + PEM parsing of the key on
// every call, exactly as a caller pays it.
// ignore_for_file: avoid_print
import 'dart:convert';
import 'package:flutter_crypto_security/flutter_crypto_security.dart';

void bench(String name, void Function() f, {int maxSeconds = 10}) {
  // Warm-up, then measure for at least 1 s (and at least 5 iterations).
  for (var i = 0; i < 3; i++) {
    f();
  }
  final sw = Stopwatch()..start();
  var iterations = 0;
  while (iterations < 5 || sw.elapsedMilliseconds < 1000) {
    f();
    iterations++;
    if (sw.elapsedMilliseconds > maxSeconds * 1000) break;
  }
  final nsPerOp = sw.elapsedMicroseconds * 1000 / iterations;
  print('$name\t${nsPerOp.round()}');
}

void main() {
  final (privateKey, publicKey) = Crypto.generateRSAKeyPair();
  final aesKey = Crypto.generateRandomBytes(32);
  final oneKib = Crypto.generateRandomBytes(1024);
  final oneMib = Crypto.generateRandomBytes(1024 * 1024);

  bench('rsa_keygen_2048', () => Crypto.generateRSAKeyPair(), maxSeconds: 3);

  final pub = Crypto.fromBase64PublicKey(publicKey);
  var ct = base64Encode(pub.encryptWithUint8ListPublicKey(aesKey));
  bench('rsa_pkcs1_encrypt_32b', () {
    Crypto.fromBase64PublicKey(publicKey).encryptWithUint8ListPublicKey(aesKey);
  });
  bench('rsa_pkcs1_decrypt_32b', () {
    Crypto.fromBase64PrivateKey(privateKey).decryptWithPrivateKey(ct);
  });

  ct = base64Encode(pub.encryptWithPublicKeyOAEP(aesKey));
  bench('rsa_oaep_encrypt_32b', () {
    Crypto.fromBase64PublicKey(publicKey).encryptWithPublicKeyOAEP(aesKey);
  });
  bench('rsa_oaep_decrypt_32b', () {
    Crypto.fromBase64PrivateKey(privateKey).decryptWithPrivateKeyOAEP(ct);
  });

  for (final (label, data) in [('1kib', oneKib), ('1mib', oneMib)]) {
    final nonce = Crypto.generateNonce();
    final (aesCt, nonceB64) = Crypto.encryptWithAES(aesKey, nonce, data);
    bench('aes_gcm_encrypt_$label', () {
      Crypto.encryptWithAES(aesKey, Crypto.generateNonce(), data);
    });
    bench('aes_gcm_decrypt_$label', () {
      Crypto.decryptWithAESBytes(
          aesKey, base64Decode(nonceB64), base64Decode(aesCt));
    });
  }

  final sig = Crypto.sign(privateKey, oneKib);
  bench('sign_sha256_1kib', () => Crypto.sign(privateKey, oneKib));
  bench('verify_sha256_1kib', () {
    if (!Crypto.verify(publicKey, oneKib, sig)) throw StateError('bad sig');
  });

  final env = Crypto.encryptEnvelope(
    recipientPublicKey: publicKey,
    payload: oneKib,
    senderPrivateKey: privateKey,
  );
  bench('envelope_encrypt_signed_1kib', () {
    Crypto.encryptEnvelope(
      recipientPublicKey: publicKey,
      payload: oneKib,
      senderPrivateKey: privateKey,
    );
  });
  bench('envelope_decrypt_verified_1kib', () {
    Crypto.decryptEnvelope(
      recipientPrivateKey: privateKey,
      envelope: env,
      senderPublicKey: publicKey,
    );
  });
}
