part of '../../encrypt.dart';

/// Wraps the Salsa20 Engine.
///
/// Security note: Salsa20 is a stream cipher that provides confidentiality
/// only and does **not** authenticate the ciphertext. Used on its own it
/// offers no tamper resistance. Prefer an authenticated construction such as
/// AES-GCM ([AESMode.gcm]) or [Fernet] when integrity matters.
class Salsa20 implements Algorithm {
  final Key key;

  final Salsa20Engine _cipher = Salsa20Engine();

  Salsa20(this.key);

  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData}) {
    if (iv == null) {
      throw StateError('IV is required.');
    }

    _cipher
      ..reset()
      ..init(true, _buildParams(iv));

    return Encrypted(_cipher.process(bytes));
  }

  @override
  Uint8List decrypt(Encrypted encrypted, {IV? iv, Uint8List? associatedData}) {
    if (iv == null) {
      throw StateError('IV is required.');
    }

    _cipher
      ..reset()
      ..init(false, _buildParams(iv));

    return _cipher.process(encrypted.bytes);
  }

  ParametersWithIV<KeyParameter> _buildParams(IV iv) {
    return ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes);
  }
}
