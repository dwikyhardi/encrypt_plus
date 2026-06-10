part of '../../encrypt.dart';

/// Wraps the Fernet Algorithm.
class Fernet implements Algorithm {
  final _maxClockSkew = 60;

  late final Key _signKey;
  late final Key _encryptionKey;
  late final Clock _clock;

  Fernet(Key key, {Clock? clock}) {
    if (key.length != 32) {
      throw StateError('Fernet key must be 32 url-safe base64-encoded bytes.');
    }
    _signKey = Key(Uint8List.fromList(key.bytes.sublist(0, 16)));
    _encryptionKey = Key(Uint8List.fromList(key.bytes.sublist(16)));
    if (clock == null) {
      _clock = Clock();
    } else {
      _clock = clock;
    }
  }

  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData}) {
    if (iv == null) {
      iv = IV.fromSecureRandom(16);
    }
    int currentTime = (_clock.now().millisecondsSinceEpoch / 1000).round();
    final encryptedBytes = _encryptFromParts(bytes, currentTime, iv);
    return Encrypted(encryptedBytes);
  }

  @override
  Uint8List decrypt(
    Encrypted encrypted, {
    IV? iv,
    Uint8List? associatedData,
    int? ttl,
  }) {
    final data = encrypted.bytes;
    if (data.first != 0x80) {
      throw StateError('Invalid token');
    }
    final ts = extractTimestamp(data);
    final now = (_clock.now().millisecondsSinceEpoch / 1000).round();
    if (ttl != null && ts + ttl < now) {
      throw StateError('Invalid token');
    }
    if (now + _maxClockSkew < ts) {
      throw StateError('Invalid token');
    }
    _verifySignature(data);
    if (iv != null) {
      // Fernet-specific: the IV is part of the token and must not be supplied
      // by the caller, unlike the optional `iv` in the generic
      // [Algorithm.decrypt] contract.
      throw StateError('IV must be inferred from token');
    }
    iv = IV(Uint8List.fromList(data.sublist(9, 25)));
    final length = data.length;
    final ciphertext =
        Encrypted(Uint8List.fromList(data.sublist(25, length - 32)));
    final aes = AES(_encryptionKey, mode: AESMode.cbc);
    final decrypted = aes.decrypt(ciphertext, iv: iv);
    return decrypted;
  }

  int extractTimestamp(Uint8List data) {
    final tsBytes = data.sublist(1, 9);
    var buffer = Uint8List.fromList(tsBytes).buffer;
    var bdata = ByteData.view(buffer);
    try {
      return bdata.getUint64(0, Endian.big);
    } catch (_) {
      // in dart2js there is no getUint64(), so fall back and improvise.
      //  Note this is not perfect as dart2js only has doubles, no 64bit ints,
      //  but this is only going to be compared to a .now().millisecondsSinceEpoch
      //  timestamp in and int so we don't need to worry about being
      //  larger than max int (of js double) we can store because
      //  .now().millisecondsSinceEpoch would have the same
      //  overloading problem -we'll all be dead when it overflows
      //  (max int of double/millseconds in year
      //   =9007199254740991 / 3.154e+10 = 285580 years from 1970)
      final int hi = bdata.getUint32(0, Endian.big);
      final int low = bdata.getUint32(4, Endian.big);
      return (hi << 32 | low);
    }
  }

  void _verifySignature(Uint8List data) {
    final length = data.length;
    final parts = data.sublist(0, length - 32);
    final _digest = data.sublist(length - 32);
    var hmac = Hmac(sha256, _signKey.bytes);
    final digestConverted = hmac.convert(parts).bytes;
    // Constant-time comparison to avoid leaking information through timing
    // (CWE-208). A short-circuiting comparison would let an attacker forge a
    // valid HMAC by measuring how long verification takes per byte.
    if (!_constantTimeEquals(_digest, digestConverted)) {
      throw StateError('Invalid token');
    }
  }

  /// Compares two byte sequences in constant time.
  ///
  /// The execution time depends only on the length of [a] and never on the
  /// position of the first differing byte, preventing timing attacks.
  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) {
      return false;
    }
    var mismatch = 0;
    for (var i = 0; i < a.length; i++) {
      mismatch |= a[i] ^ b[i];
    }
    return mismatch == 0;
  }

  Uint8List _encryptFromParts(Uint8List bytes, int currentTime, IV iv) {
    final aes = AES(_encryptionKey, mode: AESMode.cbc);
    final cipherText = aes.encrypt(bytes, iv: iv);
    // convert epoch timestamp to binary data, in bytes
    var buffer = Uint8List(8).buffer;
    var bdata = ByteData.view(buffer);
    try {
      bdata.setUint64(0, currentTime, Endian.big);
    } catch (_) {
      // in dart2js there is no setUint64(), so fall back and improvise.
      final int hi = (currentTime >> 32) & 0xffffffff;
      final int low = currentTime & 0xffffffff;
      bdata.setUint32(0, hi, Endian.big);
      bdata.setUint32(4, low, Endian.big);
    }
    final currentTimeBytes = bdata.buffer.asUint8List();

    final parts = [0x80, ...currentTimeBytes, ...iv.bytes, ...cipherText.bytes];
    var hmac = Hmac(sha256, _signKey.bytes);
    var digest = hmac.convert(parts).bytes;
    final result = [...parts, ...Uint8List.fromList(digest)];
    return Uint8List.fromList(result);
  }
}
