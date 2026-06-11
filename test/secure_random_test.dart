import 'package:encryptor_plus/encrypt.dart';
import 'package:test/test.dart';

void main() {
  test('SecureRandom', () {
    final length = 16;
    final secureRandom = SecureRandom(length);

    expect(secureRandom.length, same(length));
  });
}
