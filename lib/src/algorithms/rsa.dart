part of '../../encrypt.dart';

// Abstract class for encryption and signing.
abstract class AbstractRSA {
  final RSAPublicKey? publicKey;
  final RSAPrivateKey? privateKey;
  PublicKeyParameter<RSAPublicKey>? get _publicKeyParams =>
      publicKey != null ? PublicKeyParameter(publicKey!) : null;
  PrivateKeyParameter<RSAPrivateKey>? get _privateKeyParams =>
      privateKey != null ? PrivateKeyParameter(privateKey!) : null;
  late final AsymmetricBlockCipher _cipher;

  // ignore: non_constant_identifier_names
  AsymmetricBlockCipher _OAEPCipher(RSADigest digest) {
    switch (digest) {
      case RSADigest.SHA256:
        return OAEPEncoding.withSHA256(RSAEngine());
      case RSADigest.SHA512:
        return OAEPEncoding.withCustomDigest(
          () => SHA512Digest(),
          RSAEngine(),
        );
      case RSADigest.SHA1:
      default:
        return OAEPEncoding.withSHA1(RSAEngine());
    }
  }

  AbstractRSA({
    this.publicKey,
    this.privateKey,
    RSAEncoding encoding = RSAEncoding.OAEP,
    RSADigest digest = RSADigest.SHA256,
  }) {
    _cipher = encoding == RSAEncoding.OAEP
        ? _OAEPCipher(digest)
        : PKCS1Encoding(RSAEngine());
  }
}

/// Wraps the RSA Engine Algorithm.
///
/// Defaults to [RSAEncoding.OAEP] with a [RSADigest.SHA256] digest. OAEP is the
/// recommended padding for RSA encryption; the legacy [RSAEncoding.PKCS1]
/// (PKCS#1 v1.5) padding is vulnerable to Bleichenbacher padding-oracle
/// attacks and should only be used for backwards compatibility.
class RSA extends AbstractRSA implements Algorithm {
  RSA(
      {RSAPublicKey? publicKey,
      RSAPrivateKey? privateKey,
      RSAEncoding encoding = RSAEncoding.OAEP,
      RSADigest digest = RSADigest.SHA256})
      : super(
          publicKey: publicKey,
          privateKey: privateKey,
          encoding: encoding,
          digest: digest,
        );

  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData}) {
    if (publicKey == null) {
      throw StateError('Can\'t encrypt without a public key, null given.');
    }

    _cipher
      ..reset()
      ..init(true, _publicKeyParams!);

    return Encrypted(_cipher.process(bytes));
  }

  @override
  Uint8List decrypt(Encrypted encrypted, {IV? iv, Uint8List? associatedData}) {
    if (privateKey == null) {
      throw StateError('Can\'t decrypt without a private key, null given.');
    }

    _cipher
      ..reset()
      ..init(false, _privateKeyParams!);

    return _cipher.process(encrypted.bytes);
  }
}

/// Signs and verifies messages using RSASSA-PKCS1-v1_5.
///
/// The heavy lifting (PKCS#1 v1.5 padding and the ASN.1 `DigestInfo`
/// encoding/parsing) is delegated to PointyCastle's well-tested
/// [pc.RSASigner] instead of being re-implemented here. Hand-rolled DER
/// handling is notoriously error-prone and can open the door to signature
/// forgery (e.g. Bleichenbacher-style) attacks when edge cases are missed.
class RSASigner extends AbstractRSA implements SignerAlgorithm {
  final RSASignDigest digest;
  final pc.RSASigner _signer;

  RSASigner(this.digest, {RSAPublicKey? publicKey, RSAPrivateKey? privateKey})
      : _signer = pc.RSASigner(
          _rsaSignDigestConfig[digest]!.factory(),
          _rsaSignDigestConfig[digest]!.identifierHex,
        ),
        super(publicKey: publicKey, privateKey: privateKey);

  @override
  Encrypted sign(Uint8List bytes) {
    if (privateKey == null) {
      throw StateError('Can\'t sign without a private key, null given.');
    }

    _signer
      ..reset()
      ..init(true, _privateKeyParams!);

    return Encrypted(_signer.generateSignature(bytes).bytes);
  }

  @override
  bool verify(Uint8List bytes, Encrypted signature) {
    if (publicKey == null) {
      throw StateError('Can\'t verify without a public key, null given.');
    }

    _signer
      ..reset()
      ..init(false, _publicKeyParams!);

    return _signer.verifySignature(bytes, RSASignature(signature.bytes));
  }
}

enum RSAEncoding {
  PKCS1,
  OAEP,
}

enum RSADigest {
  SHA1,
  SHA256,
  SHA512,
}

enum RSASignDigest {
  SHA256,
  SHA512,
}

/// DER-encoded ASN.1 digest algorithm identifiers (the `06 ...` OID element)
/// together with the matching digest factory, as expected by
/// [pc.RSASigner].
final _rsaSignDigestConfig = <RSASignDigest, _RSASignConfig>{
  RSASignDigest.SHA256:
      _RSASignConfig('0609608648016503040201', () => SHA256Digest()),
  RSASignDigest.SHA512:
      _RSASignConfig('0609608648016503040203', () => SHA512Digest()),
};

class _RSASignConfig {
  final String identifierHex;
  final Digest Function() factory;

  _RSASignConfig(this.identifierHex, this.factory);
}

/// RSA PEM parser.
class RSAKeyParser {
  /// Parses the PEM key no matter it is public or private, it will figure it out.
  RSAAsymmetricKey parse(String key) {
    final rows = key.split(RegExp(r'\r\n?|\n'));
    final header = rows.first;

    if (header == '-----BEGIN RSA PUBLIC KEY-----') {
      return _parsePublic(_parseSequence(rows));
    }

    if (header == '-----BEGIN PUBLIC KEY-----') {
      return _parsePublic(_pkcs8PublicSequence(_parseSequence(rows)));
    }

    if (header == '-----BEGIN RSA PRIVATE KEY-----') {
      return _parsePrivate(_parseSequence(rows));
    }

    if (header == '-----BEGIN PRIVATE KEY-----') {
      return _parsePrivate(_pkcs8PrivateSequence(_parseSequence(rows)));
    }

    throw FormatException('Unable to parse key, invalid format.', header);
  }

  RSAAsymmetricKey _parsePublic(ASN1Sequence sequence) {
    final modulus = (sequence.elements[0] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;

    return RSAPublicKey(modulus, exponent);
  }

  RSAAsymmetricKey _parsePrivate(ASN1Sequence sequence) {
    final modulus = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[3] as ASN1Integer).valueAsBigInteger;
    final p = (sequence.elements[4] as ASN1Integer).valueAsBigInteger;
    final q = (sequence.elements[5] as ASN1Integer).valueAsBigInteger;

    return RSAPrivateKey(modulus, exponent, p, q);
  }

  ASN1Sequence _parseSequence(List<String> rows) {
    final keyText = rows
        .skipWhile((row) => row.startsWith('-----BEGIN'))
        .takeWhile((row) => !row.startsWith('-----END'))
        .map((row) => row.trim())
        .join('');

    final keyBytes = Uint8List.fromList(convert.base64.decode(keyText));
    final asn1Parser = ASN1Parser(keyBytes);

    return asn1Parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PublicSequence(ASN1Sequence sequence) {
    final ASN1Object bitString = sequence.elements[1];
    final bytes = bitString.valueBytes().sublist(1);
    final parser = ASN1Parser(Uint8List.fromList(bytes));

    return parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PrivateSequence(ASN1Sequence sequence) {
    final ASN1Object bitString = sequence.elements[2];
    final bytes = bitString.valueBytes();
    final parser = ASN1Parser(bytes);

    return parser.nextObject() as ASN1Sequence;
  }
}
