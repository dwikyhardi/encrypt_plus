part of '../encrypt.dart';

/// Wraps Algorithms in a unique Container.
class Encrypter {
  final Algorithm algo;

  Encrypter(this.algo);

  /// Calls [encrypt] on the wrapped Algorithm using a raw binary.
  Encrypted encryptBytes(List<int> input, {IV? iv, Uint8List? associatedData}) {
    if (input is Uint8List) {
      return algo.encrypt(input, iv: iv, associatedData: associatedData);
    }

    return algo.encrypt(
      Uint8List.fromList(input),
      iv: iv,
      associatedData: associatedData,
    );
  }

  /// Calls [encrypt] on the wrapped Algorithm.
  Encrypted encrypt(
    String input, {
    IV? iv,
    Uint8List? associatedData,
  }) {
    return encryptBytes(
      convert.utf8.encode(input),
      iv: iv,
      associatedData: associatedData,
    );
  }

  /// Calls [decrypt] on the wrapped Algorithm without UTF-8 decoding.
  List<int> decryptBytes(Encrypted encrypted,
      {IV? iv, Uint8List? associatedData}) {
    return algo
        .decrypt(encrypted, iv: iv, associatedData: associatedData)
        .toList();
  }

  /// Calls [decrypt] on the wrapped Algorithm.
  ///
  /// By default [allowMalformed] is `false`, so a tampered or corrupted
  /// ciphertext that does not decode as valid UTF-8 surfaces a
  /// [FormatException] instead of being silently replaced with U+FFFD
  /// characters. This matters for unauthenticated modes where the decoder is
  /// the only thing that might notice corruption. Pass `allowMalformed: true`
  /// to opt back into lenient decoding.
  String decrypt(
    Encrypted encrypted, {
    IV? iv,
    Uint8List? associatedData,
    bool allowMalformed = false,
  }) {
    return convert.utf8.decode(
      decryptBytes(encrypted, iv: iv, associatedData: associatedData),
      allowMalformed: allowMalformed,
    );
  }

  /// Sugar for `decrypt(Encrypted.fromBase16(encoded))`.
  String decrypt16(String encoded,
      {IV? iv, Uint8List? associatedData, bool allowMalformed = false}) {
    return decrypt(
      Encrypted.fromBase16(encoded),
      iv: iv,
      associatedData: associatedData,
      allowMalformed: allowMalformed,
    );
  }

  /// Sugar for `decrypt(Encrypted.fromBase64(encoded))`.
  String decrypt64(String encoded,
      {IV? iv, Uint8List? associatedData, bool allowMalformed = false}) {
    return decrypt(
      Encrypted.fromBase64(encoded),
      iv: iv,
      associatedData: associatedData,
      allowMalformed: allowMalformed,
    );
  }
}
