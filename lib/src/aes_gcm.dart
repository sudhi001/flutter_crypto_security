import 'dart:typed_data';

import 'package:pointycastle/export.dart' show AESEngine, KeyParameter;

/// AES-GCM (NIST SP 800-38D) with a 12-byte nonce and a 128-bit tag.
///
/// PointyCastle's `GCMBlockCipher` multiplies in GF(2^128) one bit at a time
/// and manages ~1 MB/s. This implementation keeps PointyCastle's AES block
/// cipher but uses Shoup's 4-bit table method for GHASH (the same approach as
/// Go's `crypto/cipher`), which is roughly 15x faster. All arithmetic is done
/// on 32-bit words so it also runs correctly on the web (dart2js).
class AesGcm {
  static const int nonceSize = 12;
  static const int tagSize = 16;
  static const int _blockSize = 16;

  final AESEngine _aes;
  final Uint32List _productTable; // 16 entries x 4 words (h1, h0, l1, l0)

  AesGcm._(this._aes, this._productTable);

  /// Creates a cipher for a 16-, 24- or 32-byte AES [key].
  factory AesGcm(Uint8List key) {
    final aes = AESEngine()..init(true, KeyParameter(key));
    final h = Uint8List(_blockSize);
    aes.processBlock(Uint8List(_blockSize), 0, h, 0);
    return AesGcm._(aes, _buildProductTable(h));
  }

  /// Encrypts [plaintext] and returns `ciphertext || tag`.
  Uint8List encrypt(Uint8List nonce, Uint8List plaintext, {Uint8List? aad}) {
    _checkNonce(nonce);
    final out = Uint8List(plaintext.length + tagSize);
    final counter = _initialCounter(nonce);
    _ctr(counter, plaintext, out);
    final tag = _tag(
        nonce, aad ?? _empty, Uint8List.sublistView(out, 0, plaintext.length));
    out.setRange(plaintext.length, out.length, tag);
    return out;
  }

  /// Verifies the tag of `ciphertext || tag` and returns the plaintext.
  ///
  /// Throws [ArgumentError] when the input is too short and [StateError]
  /// when authentication fails (wrong key, wrong nonce or tampered data).
  Uint8List decrypt(Uint8List nonce, Uint8List data, {Uint8List? aad}) {
    _checkNonce(nonce);
    if (data.length < tagSize) {
      throw ArgumentError('AES-GCM input shorter than the 16-byte tag');
    }
    final ciphertext = Uint8List.sublistView(data, 0, data.length - tagSize);
    final expected = _tag(nonce, aad ?? _empty, ciphertext);
    var diff = 0;
    for (var i = 0; i < tagSize; i++) {
      diff |= expected[i] ^ data[ciphertext.length + i];
    }
    if (diff != 0) {
      throw StateError('AES-GCM authentication failed');
    }
    final out = Uint8List(ciphertext.length);
    _ctr(_initialCounter(nonce), ciphertext, out);
    return out;
  }

  // ----------------------------------------------------------------- CTR

  static final Uint8List _empty = Uint8List(0);

  static void _checkNonce(Uint8List nonce) {
    if (nonce.length != nonceSize) {
      throw ArgumentError(
          'AES-GCM nonce must be $nonceSize bytes, got ${nonce.length}');
    }
  }

  /// J0 = nonce || 0x00000001
  static Uint8List _initialCounter(Uint8List nonce) {
    final counter = Uint8List(_blockSize);
    counter.setRange(0, nonceSize, nonce);
    counter[15] = 1;
    return counter;
  }

  static void _increment(Uint8List counter) {
    for (var i = 15; i >= 12; i--) {
      counter[i] = (counter[i] + 1) & 0xff;
      if (counter[i] != 0) break;
    }
  }

  /// out[0..input.length) = input XOR keystream, starting at inc32(counter).
  void _ctr(Uint8List counter, Uint8List input, Uint8List out) {
    final keystream = Uint8List(_blockSize);
    var offset = 0;
    while (offset < input.length) {
      _increment(counter);
      _aes.processBlock(counter, 0, keystream, 0);
      final n = input.length - offset < _blockSize
          ? input.length - offset
          : _blockSize;
      for (var i = 0; i < n; i++) {
        out[offset + i] = input[offset + i] ^ keystream[i];
      }
      offset += n;
    }
  }

  // --------------------------------------------------------------- GHASH

  /// T = E(K, J0) XOR GHASH_H(aad || pad || ciphertext || pad || len64(aad) || len64(ciphertext))
  Uint8List _tag(Uint8List nonce, Uint8List aad, Uint8List ciphertext) {
    final y = Uint32List(4);
    _ghashUpdate(y, aad);
    _ghashUpdate(y, ciphertext);

    final lengths = Uint8List(_blockSize);
    _putUint64(lengths, 0, aad.length * 8);
    _putUint64(lengths, 8, ciphertext.length * 8);
    _ghashBlock(y, lengths, 0);

    final tag = Uint8List(_blockSize);
    _aes.processBlock(_initialCounter(nonce), 0, tag, 0);
    final s = ByteData.view(tag.buffer);
    for (var i = 0; i < 4; i++) {
      s.setUint32(i * 4, s.getUint32(i * 4) ^ y[i]);
    }
    return tag;
  }

  void _ghashUpdate(Uint32List y, Uint8List data) {
    final full = data.length - data.length % _blockSize;
    for (var off = 0; off < full; off += _blockSize) {
      _ghashBlock(y, data, off);
    }
    if (full < data.length) {
      final last = Uint8List(_blockSize)
        ..setRange(0, data.length - full, data, full);
      _ghashBlock(y, last, 0);
    }
  }

  /// y = (y XOR block) * H, with the block taken from data[off..off+16).
  void _ghashBlock(Uint32List y, Uint8List data, int off) {
    final view = ByteData.sublistView(data, off, off + _blockSize);
    y[0] ^= view.getUint32(0);
    y[1] ^= view.getUint32(4);
    y[2] ^= view.getUint32(8);
    y[3] ^= view.getUint32(12);
    _multiply(y);
  }

  /// y = y * H using the 4-bit product table (Shoup's method, as in OpenSSL's
  /// gcm_gmult_4bit). Words are (a1, a0, b1, b0): a1 holds bytes 0..3 of the
  /// big-endian block, a0 bytes 4..7, b1 bytes 8..11 and b0 bytes 12..15.
  void _multiply(Uint32List y) {
    var za1 = 0, za0 = 0, zb1 = 0, zb0 = 0;
    final t = _productTable;

    // Consume nibbles from byte 15 (low nibble first) back to byte 0: first
    // the second 64-bit half (b), then the first (a).
    for (var half = 1; half >= 0; half--) {
      final wordHi = y[half * 2];
      final wordLo = y[half * 2 + 1];
      for (var j = 0; j < 16; j++) {
        final nibble = j < 8
            ? (wordLo >>> (j * 4)) & 0xf
            : (wordHi >>> ((j - 8) * 4)) & 0xf;

        // z >>= 4 across (a:b); the dropped nibble is folded back via the
        // reduction table into the top of a.
        final rem = zb0 & 0xf;
        zb0 = (zb0 >>> 4) | ((zb1 & 0xf) << 28);
        zb1 = (zb1 >>> 4) | ((za0 & 0xf) << 28);
        za0 = (za0 >>> 4) | ((za1 & 0xf) << 28);
        za1 = (za1 >>> 4) ^ (_reductionTable[rem] << 16);

        final idx = nibble * 4;
        za1 ^= t[idx];
        za0 ^= t[idx + 1];
        zb1 ^= t[idx + 2];
        zb0 ^= t[idx + 3];
      }
    }
    y[0] = za1;
    y[1] = za0;
    y[2] = zb1;
    y[3] = zb0;
  }

  /// productTable[reverseBits(i)] = i * H for the 4-bit values i.
  static Uint32List _buildProductTable(Uint8List h) {
    final table = Uint32List(16 * 4);
    final hv = ByteData.view(h.buffer);
    final hw = [
      hv.getUint32(0),
      hv.getUint32(4),
      hv.getUint32(8),
      hv.getUint32(12),
    ];

    void set(int i, List<int> v) => table.setRange(i * 4, i * 4 + 4, v);
    List<int> get(int i) => table.sublist(i * 4, i * 4 + 4);

    set(_reverseBits(1), hw);
    for (var i = 2; i < 16; i += 2) {
      set(_reverseBits(i), _double(get(_reverseBits(i ~/ 2))));
      final d = get(_reverseBits(i));
      set(_reverseBits(i + 1), [
        d[0] ^ hw[0],
        d[1] ^ hw[1],
        d[2] ^ hw[2],
        d[3] ^ hw[3],
      ]);
    }
    return table;
  }

  /// x * 2 in GF(2^128) with GCM's bit-reflected representation: a right
  /// shift across (a:b) with the bit falling off b0 reduced by 0xe1 into a1.
  static List<int> _double(List<int> x) {
    final a1 = x[0], a0 = x[1], b1 = x[2], b0 = x[3];
    final msbSet = b0 & 1 == 1;
    final db0 = (b0 >>> 1) | ((b1 & 1) << 31);
    final db1 = (b1 >>> 1) | ((a0 & 1) << 31);
    final da0 = (a0 >>> 1) | ((a1 & 1) << 31);
    var da1 = a1 >>> 1;
    if (msbSet) da1 ^= 0xe1000000;
    return [da1, da0, db1, db0];
  }

  static int _reverseBits(int i) =>
      ((i & 1) << 3) | ((i & 2) << 1) | ((i & 4) >>> 1) | ((i & 8) >>> 3);

  static const List<int> _reductionTable = [
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, //
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
  ];

  static void _putUint64(Uint8List out, int off, int value) {
    // Split into two 32-bit halves so it also works on the web.
    final hi = value ~/ 0x100000000;
    final lo = value & 0xffffffff;
    final view = ByteData.view(out.buffer, out.offsetInBytes + off, 8);
    view.setUint32(0, hi);
    view.setUint32(4, lo);
  }
}
