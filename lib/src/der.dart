import 'dart:typed_data';

/// Minimal DER reader/writer covering what RSA key files need:
/// SEQUENCE, INTEGER, BIT STRING, OCTET STRING, OBJECT IDENTIFIER and NULL.
class DerTag {
  static const int integer = 0x02;
  static const int bitString = 0x03;
  static const int octetString = 0x04;
  static const int nullValue = 0x05;
  static const int oid = 0x06;
  static const int sequence = 0x30;
}

/// A decoded DER element.
class DerElement {
  final int tag;
  final Uint8List value;

  DerElement(this.tag, this.value);

  bool get isSequence => tag == DerTag.sequence;

  /// Parses the children of a SEQUENCE.
  List<DerElement> get children {
    if (!isSequence) {
      throw const FormatException('DER element is not a SEQUENCE');
    }
    return DerReader(value).readAll();
  }

  /// Interprets an INTEGER as an unsigned big-endian value.
  BigInt get bigInt {
    if (tag != DerTag.integer) {
      throw const FormatException('DER element is not an INTEGER');
    }
    return _bytesToBigInt(value);
  }

  /// Interprets a BIT STRING and returns its content bytes (unused-bits
  /// octet stripped).
  Uint8List get bitStringBytes {
    if (tag != DerTag.bitString || value.isEmpty) {
      throw const FormatException('DER element is not a BIT STRING');
    }
    return Uint8List.sublistView(value, 1);
  }

  /// Returns the dotted-string form of an OBJECT IDENTIFIER.
  String get oidString {
    if (tag != DerTag.oid || value.isEmpty) {
      throw const FormatException('DER element is not an OBJECT IDENTIFIER');
    }
    final parts = <int>[value[0] ~/ 40, value[0] % 40];
    var acc = 0;
    for (var i = 1; i < value.length; i++) {
      acc = (acc << 7) | (value[i] & 0x7f);
      if (value[i] & 0x80 == 0) {
        parts.add(acc);
        acc = 0;
      }
    }
    return parts.join('.');
  }
}

/// Sequential DER reader over a byte buffer.
class DerReader {
  final Uint8List _bytes;
  int _pos = 0;

  DerReader(this._bytes);

  bool get hasMore => _pos < _bytes.length;

  DerElement next() {
    if (_pos >= _bytes.length) {
      throw const FormatException('Unexpected end of DER data');
    }
    final tag = _bytes[_pos++];
    if (_pos >= _bytes.length) {
      throw const FormatException('Unexpected end of DER data');
    }
    var length = _bytes[_pos++];
    if (length & 0x80 != 0) {
      final numBytes = length & 0x7f;
      if (numBytes == 0 || numBytes > 4 || _pos + numBytes > _bytes.length) {
        throw const FormatException('Invalid DER length');
      }
      length = 0;
      for (var i = 0; i < numBytes; i++) {
        length = (length << 8) | _bytes[_pos++];
      }
    }
    if (_pos + length > _bytes.length) {
      throw const FormatException('DER length exceeds buffer');
    }
    final value = Uint8List.sublistView(_bytes, _pos, _pos + length);
    _pos += length;
    return DerElement(tag, value);
  }

  List<DerElement> readAll() {
    final out = <DerElement>[];
    while (hasMore) {
      out.add(next());
    }
    return out;
  }
}

/// Helpers producing DER-encoded elements.
class DerWriter {
  static Uint8List _encode(int tag, List<int> content) {
    final out = BytesBuilder(copy: false);
    out.addByte(tag);
    final len = content.length;
    if (len < 0x80) {
      out.addByte(len);
    } else {
      final lenBytes = <int>[];
      var l = len;
      while (l > 0) {
        lenBytes.insert(0, l & 0xff);
        l >>= 8;
      }
      out.addByte(0x80 | lenBytes.length);
      out.add(lenBytes);
    }
    out.add(content);
    return out.toBytes();
  }

  static Uint8List sequence(List<Uint8List> elements) {
    final content = BytesBuilder(copy: false);
    for (final e in elements) {
      content.add(e);
    }
    return _encode(DerTag.sequence, content.toBytes());
  }

  static Uint8List integer(BigInt value) {
    var bytes = _bigIntToBytes(value);
    // Positive INTEGERs whose top bit is set need a leading zero byte.
    if (bytes.isEmpty || bytes[0] & 0x80 != 0) {
      bytes = Uint8List.fromList([0, ...bytes]);
    }
    return _encode(DerTag.integer, bytes);
  }

  static Uint8List bitString(Uint8List bytes) =>
      _encode(DerTag.bitString, [0, ...bytes]);

  static Uint8List octetString(Uint8List bytes) =>
      _encode(DerTag.octetString, bytes);

  static Uint8List nullValue() => _encode(DerTag.nullValue, const []);

  static Uint8List oid(String dotted) {
    final parts = dotted.split('.').map(int.parse).toList();
    final out = <int>[parts[0] * 40 + parts[1]];
    for (final p in parts.skip(2)) {
      final chunk = <int>[];
      var v = p;
      chunk.insert(0, v & 0x7f);
      v >>= 7;
      while (v > 0) {
        chunk.insert(0, (v & 0x7f) | 0x80);
        v >>= 7;
      }
      out.addAll(chunk);
    }
    return _encode(DerTag.oid, out);
  }
}

BigInt _bytesToBigInt(Uint8List bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

Uint8List _bigIntToBytes(BigInt value) {
  if (value == BigInt.zero) {
    return Uint8List.fromList([0]);
  }
  final byteLength = (value.bitLength + 7) ~/ 8;
  final out = Uint8List(byteLength);
  var v = value;
  final mask = BigInt.from(0xff);
  for (var i = byteLength - 1; i >= 0; i--) {
    out[i] = (v & mask).toInt();
    v >>= 8;
  }
  return out;
}

/// Encodes a BigInt as a fixed-width unsigned big-endian array.
Uint8List bigIntToFixedBytes(BigInt value, int length) {
  final bytes = _bigIntToBytes(value);
  if (bytes.length > length) {
    throw ArgumentError('value does not fit in $length bytes');
  }
  final out = Uint8List(length);
  out.setRange(length - bytes.length, length, bytes);
  return out;
}
