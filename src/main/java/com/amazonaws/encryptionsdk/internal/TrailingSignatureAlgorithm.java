package com.amazonaws.encryptionsdk.internal;

import static com.amazonaws.encryptionsdk.internal.Utils.bigIntegerToByteArray;
import static com.amazonaws.encryptionsdk.internal.Utils.encodeBase64String;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static org.apache.commons.lang3.Validate.isInstanceOf;
import static org.apache.commons.lang3.Validate.notNull;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

/**
 * Provides a consistent interface across various trailing signature algorithms.
 *
 * <p>NOTE: This is not a stable API and may undergo breaking changes in the future.
 */
public abstract class TrailingSignatureAlgorithm {

  private TrailingSignatureAlgorithm() {
    /* Do not allow arbitrary subclasses */
  }

  public abstract String getMessageDigestAlgorithm();

  public abstract String getRawSignatureAlgorithm();

  public abstract String getHashAndSignAlgorithm();

  public abstract PublicKey deserializePublicKey(String keyString);

  public abstract String serializePublicKey(PublicKey key);

  public abstract KeyPair generateKey() throws GeneralSecurityException;

  /* Standards for Efficient Cryptography over a prime field */
  private static final String SEC_PRIME_FIELD_PREFIX = "secp";

  private static final class ECDSASignatureAlgorithm extends TrailingSignatureAlgorithm {
    private final ECGenParameterSpec ecSpec;
    private final ECParameterSpec ecParameterSpec;
    private final String messageDigestAlgorithm;
    private final String hashAndSignAlgorithm;
    private static final String ELLIPTIC_CURVE_ALGORITHM = "EC";
    /* Constants used by SEC-1 v2 point compression and decompression algorithms */
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);

    private ECDSASignatureAlgorithm(
        ECGenParameterSpec ecSpec, String messageDigestAlgorithm, String hashAndSignAlgorithm) {
      if (!ecSpec.getName().startsWith(SEC_PRIME_FIELD_PREFIX)) {
        throw new IllegalStateException("Non-prime curves are not supported at this time");
      }

      this.ecSpec = ecSpec;
      this.messageDigestAlgorithm = messageDigestAlgorithm;
      this.hashAndSignAlgorithm = hashAndSignAlgorithm;

      try {
        final AlgorithmParameters parameters =
            AlgorithmParameters.getInstance(ELLIPTIC_CURVE_ALGORITHM);
        parameters.init(ecSpec);
        this.ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
      } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
        throw new IllegalStateException("Invalid algorithm", e);
      }
    }

    @Override
    public String toString() {
      return "ECDSASignatureAlgorithm(curve=" + ecSpec.getName() + ")";
    }

    @Override
    public String getMessageDigestAlgorithm() {
      return messageDigestAlgorithm;
    }

    @Override
    public String getRawSignatureAlgorithm() {
      return "NONEwithECDSA";
    }

    @Override
    public String getHashAndSignAlgorithm() {
      return hashAndSignAlgorithm;
    }

    /**
     * Decodes a compressed elliptic curve point as described in SEC-1 v2 section 2.3.4
     *
     * @param keyString The serialized and compressed public key
     * @return The PublicKey
     * @see <a href="http://www.secg.org/sec1-v2.pdf">http://www.secg.org/sec1-v2.pdf</a>
     */
    @Override
    public PublicKey deserializePublicKey(String keyString) {
      notNull(keyString, "keyString is required");

      final byte[] decodedKey = Utils.decodeBase64String(keyString);
      final BigInteger x = new BigInteger(1, Arrays.copyOfRange(decodedKey, 1, decodedKey.length));

      final byte compressedY = decodedKey[0];
      final BigInteger yOrder;

      if (compressedY == TWO.byteValue()) {
        yOrder = ZERO;
      } else if (compressedY == THREE.byteValue()) {
        yOrder = ONE;
      } else {
        throw new IllegalArgumentException("Compressed y value was invalid");
      }

      final BigInteger p = ((ECFieldFp) ecParameterSpec.getCurve().getField()).getP();
      final BigInteger a = ecParameterSpec.getCurve().getA();
      final BigInteger b = ecParameterSpec.getCurve().getB();

      // alpha must be equal to y^2, this is validated below
      final BigInteger alpha = x.modPow(THREE, p).add(a.multiply(x).mod(p)).add(b).mod(p);

      final BigInteger beta;
      if (p.mod(FOUR).equals(THREE)) {
        beta = alpha.modPow(p.add(ONE).divide(FOUR), p);
      } else {
        throw new IllegalArgumentException("Curve not supported at this time");
      }

      final BigInteger y = beta.mod(TWO).equals(yOrder) ? beta : p.subtract(beta);

      // Validate that Y is a root of Y^2 to prevent invalid point attacks
      if (!alpha.equals(y.modPow(TWO, p))) {
        throw new IllegalArgumentException("Y was invalid");
      }

      try {
        return KeyFactory.getInstance(ELLIPTIC_CURVE_ALGORITHM)
            .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ecParameterSpec));
      } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
        throw new IllegalStateException("Invalid algorithm", e);
      }
    }

    /**
     * Encodes a compressed elliptic curve point as described in SEC-1 v2 section 2.3.3
     *
     * @param key The Elliptic Curve public key to compress and serialize
     * @return The serialized and compressed public key
     * @see <a href="http://www.secg.org/sec1-v2.pdf">http://www.secg.org/sec1-v2.pdf</a>
     */
    @Override
    public String serializePublicKey(PublicKey key) {
      notNull(key, "key is required");
      isInstanceOf(ECPublicKey.class, key, "key must be an instance of ECPublicKey");

      final BigInteger x = ((ECPublicKey) key).getW().getAffineX();
      final BigInteger y = ((ECPublicKey) key).getW().getAffineY();
      final BigInteger compressedY = y.mod(TWO).equals(ZERO) ? TWO : THREE;

      final byte[] xBytes =
          bigIntegerToByteArray(
              x, ecParameterSpec.getCurve().getField().getFieldSize() / Byte.SIZE);

      final byte[] compressedKey = new byte[xBytes.length + 1];
      System.arraycopy(xBytes, 0, compressedKey, 1, xBytes.length);
      compressedKey[0] = compressedY.byteValue();

      return encodeBase64String(compressedKey);
    }

    @Override
    public KeyPair generateKey() throws GeneralSecurityException {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ELLIPTIC_CURVE_ALGORITHM);
      keyGen.initialize(ecSpec, Utils.getSecureRandom());

      return keyGen.generateKeyPair();
    }
  }

  private static final ECDSASignatureAlgorithm SHA256_ECDSA_P256 =
      new ECDSASignatureAlgorithm(
          new ECGenParameterSpec(SEC_PRIME_FIELD_PREFIX + "256r1"), "SHA-256", "SHA256withECDSA");
  private static final ECDSASignatureAlgorithm SHA384_ECDSA_P384 =
      new ECDSASignatureAlgorithm(
          new ECGenParameterSpec(SEC_PRIME_FIELD_PREFIX + "384r1"), "SHA-384", "SHA384withECDSA");

  public static TrailingSignatureAlgorithm forCryptoAlgorithm(CryptoAlgorithm algorithm) {
    switch (algorithm) {
      case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256:
        return SHA256_ECDSA_P256;
      case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
      case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
      case ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384:
        return SHA384_ECDSA_P384;
      default:
        throw new IllegalStateException("Algorithm does not support trailing signature");
    }
  }
}
