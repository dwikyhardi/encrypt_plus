part of '../encrypt.dart';

Uint8List decodeHexString(String input) {
  if (input.length % 2 != 0) {
    throw FormatException('Input needs to be an even length.', input);
  }

  return Uint8List.fromList(
    List.generate(
      input.length ~/ 2,
      (i) => int.parse(input.substring(i * 2, (i * 2) + 2), radix: 16),
    ).toList(),
  );
}
