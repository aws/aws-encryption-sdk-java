// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.CommittedKey;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.HmacKeyDerivationFunction;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteInfo;
import software.amazon.cryptography.materialproviders.model.HKDF;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

/**
 * Describes the cryptographic algorithms available for use in this library.
 *
 * <p>Format: CryptoAlgorithm(block size, nonce length, tag length, max content length, key algo,
 * key length, short value representing this algorithm, trailing signature alg, trailing signature
 * length)
 */
public enum CryptoAlgorithm {
  /** AES-GCM 128 */
  ALG_AES_128_GCM_IV12_TAG16_NO_KDF(0x0014),
  /** AES-GCM 192 */
  ALG_AES_192_GCM_IV12_TAG16_NO_KDF(0x0046),
  /** AES-GCM 256 */
  ALG_AES_256_GCM_IV12_TAG16_NO_KDF(0x0078),
  /** AES-GCM 128 with HKDF-SHA256 */
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256(0x0114),
  /** AES-GCM 192 with HKDF-SHA256 */
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256(0x0146),
  /** AES-GCM 256 with HKDF-SHA256 */
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256(0x0178),
  /** AES-GCM 128 with HKDF-SHA256 and ECDSA (SHA256 with the secp256r1 curve) */
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256(0x0214),
  /** AES-GCM 192 with HKDF-SHA384 ECDSA (SHA384 with the secp384r1 curve) */
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(0x0346),
  /** AES-GCM 256 with HKDF-SHA384 and ECDSA (SHA384 with the secp384r1 curve) */
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(0x0378),
  /**
   * AES-GCM 256 with HKDF-SHA512 and key commitment Note: 1.7.0 of this library only supports
   * decryption of using this crypto algorithm and does not support encryption with this algorithm
   */
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY(0x0478),
  /**
   * AES-GCM 256 with HKDF-SHA512, ECDSA (SHA384 with the secp384r1 curve) and key commitment Note:
   * 1.7.0 of this library only supports decryption of using this crypto algorithm and does not
   * support encryption with this algorithm
   */
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384(0x0578);

  private final AlgorithmSuiteInfo info;
  final MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
  final MaterialProviders materialProviders =
      MaterialProviders.builder().MaterialProvidersConfig(config).build();
  private final short value;

  CryptoAlgorithm(int value) {
    if (value > Short.MAX_VALUE || value < Short.MIN_VALUE) {
      throw new IllegalArgumentException("Invalid value " + value);
    }
    this.value = (short) value;
    this.info =
        materialProviders.GetAlgorithmSuiteInfo(ByteBuffer.allocate(2).putShort((short) value));
  }

  private static final String KEY_ALGORITHM = "AES";
  private static final String HKDF_SHA256 = "HkdfSHA256";
  private static final String HKDF_SHA384 = "HkdfSHA384";
  private static final String HKDF_SHA512 = "HkdfSHA512";
  private static final String ECDSA_P256 = "SHA256withECDSA";
  private static final String ECDSA_P384 = "SHA384withECDSA";
  private static final int BLOCK_SIZE_BYTES = 16;
  private static final int VERSION_1_MESSAGE_ID_LEN = 16;
  private static final int VERSION_2_MESSAGE_ID_LEN = 32;

  /*
   * Create a mapping between the CiphertextType object and its byte value representation. Make
   * this a static method so the map is created when the object is created. This enables fast
   * lookups of the CryptoAlgorithm given its short value representation and message format version.
   */
  private static final Map<Integer, CryptoAlgorithm> ID_MAPPING = new HashMap<>();

  static {
    for (final CryptoAlgorithm s : EnumSet.allOf(CryptoAlgorithm.class)) {
      ID_MAPPING.put(fieldsToLookupKey(s.getMessageFormatVersion(), s.getValue()), s);
    }
  }

  private static int fieldsToLookupKey(final byte messageFormatVersion, final short algorithmId) {
    // We pack the message format version and algorithm id into a single value.
    // Since the algorithm ID is a short and thus 16 bits long, we'll just
    // left shift the message format version by that amount.
    // The message format version is 8 bits, so this totals 24 bits and fits
    // within a standard 32 bit integer.
    return (messageFormatVersion << 16) | algorithmId;
  }

  /**
   * Returns the CryptoAlgorithm object that matches the given value assuming a message format
   * version of 1.
   *
   * @param value the value of the object
   * @return the CryptoAlgorithm object that matches the given value, null if no match is found.
   * @deprecated See {@link #deserialize(byte, short)}
   */
  public static CryptoAlgorithm deserialize(final byte messageFormatVersion, final short value) {
    return ID_MAPPING.get(fieldsToLookupKey(messageFormatVersion, value));
  }

  public AlgorithmSuiteId getAlgorithmSuiteId() {
    return info.id();
  }

  /** Returns the length of the message Id in the header for this algorithm. */
  public int getMessageIdLength() {
    // For now this is a derived value rather than stored explicitly
    switch (info.messageVersion()) {
      case 1:
        return VERSION_1_MESSAGE_ID_LEN;
      case 2:
        return VERSION_2_MESSAGE_ID_LEN;
      default:
        throw new UnsupportedOperationException(
            "Support for version " + info.messageVersion() + " not yet built.");
    }
  }

  /**
   * Returns the header nonce to use with this algorithm. null indicates that the header nonce is
   * not a parameter of the algorithm, and is instead stored as part of the message header.
   */
  public byte[] getHeaderNonce() {
    // For now this is a derived value rather than stored explicitly
    switch (info.messageVersion()) {
      case 1:
        return null;
      case 2:
        // V2 explicitly uses an IV of 0 in the header
        return new byte[info.encrypt().AES_GCM().ivLength()];
      default:
        throw new UnsupportedOperationException(
            "Support for version " + info.messageVersion() + " not yet built.");
    }
  }

  /** Returns the message format version associated with this algorithm suite. */
  public byte getMessageFormatVersion() {
    return (byte) (info.messageVersion() & 0xFF);
  }

  /** Returns the block size of this algorithm in bytes. */
  public int getBlockSize() {
    return BLOCK_SIZE_BYTES;
  }

  /** Returns the nonce length used in this algorithm in bytes. */
  public byte getNonceLen() {
    return (byte) info.encrypt().AES_GCM().ivLength();
  }

  /** Returns the tag length used in this algorithm in bytes. */
  public int getTagLen() {
    return info.encrypt().AES_GCM().tagLength();
  }

  /**
   * Returns the maximum content length in bytes that can be processed under a single data key in
   * this algorithm.
   */
  public long getMaxContentLen() {
    return Constants.GCM_MAX_CONTENT_LEN;
  }

  /** Returns the algorithm used for encrypting the plaintext data. */
  public String getKeyAlgo() {
    return KEY_ALGORITHM;
  }

  /** Returns the length of the key used in this algorithm in bytes. */
  public int getKeyLength() {
    return info.encrypt().AES_GCM().keyLength();
  }

  /** Returns the value used to encode this algorithm in the ciphertext. */
  public short getValue() {
    return value;
  }

  /** Returns the algorithm associated with the data key. */
  public String getDataKeyAlgo() {
    if (info.kdf().HKDF() == null) {
      return KEY_ALGORITHM;
    } else {
      String hmac = info.kdf().HKDF().hmac().name();
      switch (hmac) {
        case "SHA_256":
          return HKDF_SHA256;
        case "SHA_384":
          return HKDF_SHA384;
        case "SHA_512":
          return HKDF_SHA512;
        default:
          throw new UnsupportedOperationException(
              "Support for Data Key Algorithm:" + hmac + " not yet built");
      }
    }
  }

  /** Returns the length of the data key in bytes. */
  public int getDataKeyLength() {
    return this.getKeyLength();
  }

  /** Returns the algorithm used to calculate the trailing signature */
  public String getTrailingSignatureAlgo() {
    if (info.signature().ECDSA() == null) {
      return null;
    } else {
      String ecdsa = info.signature().ECDSA().curve().name();
      switch (ecdsa) {
        case "ECDSA_P256":
          return ECDSA_P256;
        case "ECDSA_P384":
          return ECDSA_P384;
        default:
          throw new UnsupportedOperationException(
              "Support for Data Key Algorithm:" + ecdsa + " not yet built");
      }
    }
  }

  /**
   * Returns whether data keys used with this crypto algorithm can safely be cached and reused for a
   * different message. If this returns false, reuse of data keys is likely to result in severe
   * cryptographic weaknesses, potentially even with only a single such use.
   */
  public boolean isSafeToCache() {
    return (info.kdf().HKDF() != null);
  }

  /**
   * Returns the length of the trailing signature generated by this algorithm. The actual trailing
   * signature may be shorter than this.
   */
  public short getTrailingSignatureLength() {
    if (info.signature().ECDSA() == null) {
      return 0;
    } else {
      String ecdsa = info.signature().ECDSA().curve().name();
      switch (ecdsa) {
        case "ECDSA_P256":
          return 71;
        case "ECDSA_P384":
          return 103;
        default:
          throw new UnsupportedOperationException(
              "Support for Data Key Algorithm:" + ecdsa + " not yet built");
      }
    }
  }

  public String getKeyCommitmentAlgo_() {
    HKDF keyCommitment = info.commitment().HKDF();
    if (keyCommitment == null) {
      return null;
    }
    switch (keyCommitment.hmac().name()) {
      case "SHA_512":
        return "HkdfSHA512";
      default:
        throw new UnsupportedOperationException(
            "Support for Commitment Key Algorithm:" + info.commitment().HKDF() + " not yet built");
    }
  }

  /**
   * Returns a derived value of whether a commitment value is generated with the key in order to
   * ensure key commitment.
   */
  public boolean isCommitting() {
    return info.commitment().HKDF() != null;
  }

  public int getCommitmentLength() {
    return info.commitment().HKDF() == null ? 0 : info.commitment().HKDF().inputKeyLength();
  }

  public int getCommitmentNonceLength() {
    return info.commitment().HKDF() == null ? 0 : info.commitment().HKDF().saltLength();
  }

  public int getSuiteDataLength() {
    return info.commitment().HKDF() == null ? 0 : info.commitment().HKDF().outputKeyLength();
  }

  public SecretKey getEncryptionKeyFromDataKey(
      final SecretKey dataKey, final CiphertextHeaders headers) throws InvalidKeyException {
    if (!dataKey.getAlgorithm().equalsIgnoreCase(getDataKeyAlgo())) {
      throw new InvalidKeyException(
          "DataKey of incorrect algorithm. Expected "
              + getDataKeyAlgo()
              + " but was "
              + dataKey.getAlgorithm());
    }

    // We perform key derivation differently depending on the message format version
    switch (info.messageVersion()) {
      case 1:
        return getNonCommittedEncryptionKey(dataKey, headers);
      case 2:
        return getCommittedEncryptionKey(dataKey, headers);
      default:
        throw new UnsupportedOperationException(
            "Support for message format version " + info.messageVersion() + " not yet built.");
    }
  }

  private SecretKey getCommittedEncryptionKey(
      final SecretKey dataKey, final CiphertextHeaders headers) throws InvalidKeyException {
    final CommittedKey committedKey = CommittedKey.generate(this, dataKey, headers.getMessageId());
    if (!MessageDigest.isEqual(committedKey.getCommitment(), headers.getSuiteData())) {
      throw new BadCiphertextException(
          "Key commitment validation failed. Key identity does not match the "
              + "identity asserted in the message. Halting processing of this message.");
    }
    return committedKey.getKey();
  }

  private SecretKey getNonCommittedEncryptionKey(
      final SecretKey dataKey, final CiphertextHeaders headers) throws InvalidKeyException {
    final String macAlgorithm;

    switch (this) {
      case ALG_AES_128_GCM_IV12_TAG16_NO_KDF:
      case ALG_AES_192_GCM_IV12_TAG16_NO_KDF:
      case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
        return dataKey;
      case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256:
      case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256:
      case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256:
      case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256:
        macAlgorithm = "HmacSHA256";
        break;
      case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
      case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
        macAlgorithm = "HmacSHA384";
        break;
      default:
        throw new UnsupportedOperationException("Support for " + this + " not yet built.");
    }
    if (!dataKey.getFormat().equalsIgnoreCase("RAW")) {
      throw new InvalidKeyException(
          "Currently only RAW format keys are supported for HKDF algorithms. Actual format was "
              + dataKey.getFormat());
    }
    final byte[] messageId = headers.getMessageId();
    final ByteBuffer info = ByteBuffer.allocate(messageId.length + 2);
    info.order(ByteOrder.BIG_ENDIAN);
    info.putShort(getValue());
    info.put(messageId);

    final byte[] rawDataKey = dataKey.getEncoded();
    if (rawDataKey.length != getDataKeyLength()) {
      throw new InvalidKeyException(
          "DataKey of incorrect length. Expected "
              + getDataKeyLength()
              + " but was "
              + rawDataKey.length);
    }

    final HmacKeyDerivationFunction hkdf;
    try {
      hkdf = HmacKeyDerivationFunction.getInstance(macAlgorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }

    hkdf.init(rawDataKey);
    return new SecretKeySpec(hkdf.deriveKey(info.array(), getKeyLength()), getKeyAlgo());
  }
}
