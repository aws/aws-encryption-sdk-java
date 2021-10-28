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

/**
 * Describes the cryptographic algorithms available for use in this library.
 *
 * <p>Format: CryptoAlgorithm(block size, nonce length, tag length, max content length, key algo,
 * key length, short value representing this algorithm, trailing signature alg, trailing signature
 * length)
 */
public enum CryptoAlgorithm {
  /** AES-GCM 128 */
  ALG_AES_128_GCM_IV12_TAG16_NO_KDF(
      1, 128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 16, 0x0014, "AES", 16, false),
  /** AES-GCM 192 */
  ALG_AES_192_GCM_IV12_TAG16_NO_KDF(
      1, 128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 24, 0x0046, "AES", 24, false),
  /** AES-GCM 256 */
  ALG_AES_256_GCM_IV12_TAG16_NO_KDF(
      1, 128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 32, 0x0078, "AES", 32, false),
  /** AES-GCM 128 with HKDF-SHA256 */
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256(
      1, 128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 16, 0x0114, "HkdfSHA256", 16, true),
  /** AES-GCM 192 */
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256(
      1, 128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 24, 0x0146, "HkdfSHA256", 24, true),
  /** AES-GCM 256 */
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256(
      1, 128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 32, 0x0178, "HkdfSHA256", 32, true),

  /** AES-GCM 128 with ECDSA (SHA256 with the secp256r1 curve) */
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256(
      1,
      128,
      12,
      16,
      Constants.GCM_MAX_CONTENT_LEN,
      "AES",
      16,
      0x0214,
      "HkdfSHA256",
      16,
      true,
      "SHA256withECDSA",
      71),
  /** AES-GCM 192 with ECDSA (SHA384 with the secp384r1 curve) */
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(
      1,
      128,
      12,
      16,
      Constants.GCM_MAX_CONTENT_LEN,
      "AES",
      24,
      0x0346,
      "HkdfSHA384",
      24,
      true,
      "SHA384withECDSA",
      103),
  /** AES-GCM 256 with ECDSA (SHA384 with the secp384r1 curve) */
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(
      1,
      128,
      12,
      16,
      Constants.GCM_MAX_CONTENT_LEN,
      "AES",
      32,
      0x0378,
      "HkdfSHA384",
      32,
      true,
      "SHA384withECDSA",
      103),
  /**
   * AES-GCM 256 with key commitment Note: 1.7.0 of this library only supports decryption of using
   * this crypto algorithm and does not support encryption with this algorithm
   */
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY(
      2,
      128,
      12,
      16,
      Constants.GCM_MAX_CONTENT_LEN,
      "AES",
      32,
      0x0478,
      "HkdfSHA512",
      32,
      true,
      null,
      0,
      "HkdfSHA512",
      32,
      32,
      32),
  /**
   * AES-GCM 256 with ECDSA (SHA384 with the secp384r1 curve) and key commitment Note: 1.7.0 of this
   * library only supports decryption of using this crypto algorithm and does not support encryption
   * with this algorithm
   */
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384(
      2,
      128,
      12,
      16,
      Constants.GCM_MAX_CONTENT_LEN,
      "AES",
      32,
      0x0578,
      "HkdfSHA512",
      32,
      true,
      "SHA384withECDSA",
      103,
      "HkdfSHA512",
      32,
      32,
      32);

  private final byte messageFormatVersion_;
  private final int blockSizeBits_;
  private final byte nonceLenBytes_;
  private final int tagLenBytes_;
  private final long maxContentLen_;
  private final String keyAlgo_;
  private final int keyLenBytes_;
  private final short value_;
  private final String trailingSigAlgo_;
  private final short trailingSigLen_;
  private final String dataKeyAlgo_;
  private final int dataKeyLen_;
  private final boolean safeToCache_;
  private final String keyCommitmentAlgo_;
  private final int commitmentLength_;
  private final int commitmentNonceLength_;
  private final int suiteDataLength_;

  private static final byte VERSION_1 = (byte) 1;
  private static final byte VERSION_2 = (byte) 2;
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
      ID_MAPPING.put(fieldsToLookupKey(s.messageFormatVersion_, s.value_), s);
    }
  }

  CryptoAlgorithm(
      final int messageFormatVersion,
      final int blockSizeBits,
      final int nonceLenBytes,
      final int tagLenBytes,
      final long maxContentLen,
      final String keyAlgo,
      final int keyLenBytes,
      final int value,
      final String dataKeyAlgo,
      final int dataKeyLen,
      boolean safeToCache) {
    this(
        messageFormatVersion,
        blockSizeBits,
        nonceLenBytes,
        tagLenBytes,
        maxContentLen,
        keyAlgo,
        keyLenBytes,
        value,
        dataKeyAlgo,
        dataKeyLen,
        safeToCache,
        null,
        0);
  }

  CryptoAlgorithm(
      final int messageFormatVersion,
      final int blockSizeBits,
      final int nonceLenBytes,
      final int tagLenBytes,
      final long maxContentLen,
      final String keyAlgo,
      final int keyLenBytes,
      final int value,
      final String dataKeyAlgo,
      final int dataKeyLen,
      boolean safeToCache,
      final String trailingSignatureAlgo,
      final int trailingSignatureLength) {
    this(
        messageFormatVersion,
        blockSizeBits,
        nonceLenBytes,
        tagLenBytes,
        maxContentLen,
        keyAlgo,
        keyLenBytes,
        value,
        dataKeyAlgo,
        dataKeyLen,
        safeToCache,
        trailingSignatureAlgo,
        trailingSignatureLength,
        null,
        0,
        0,
        0);
  }

  CryptoAlgorithm(
      final int messageFormatVersion,
      final int blockSizeBits,
      final int nonceLenBytes,
      final int tagLenBytes,
      final long maxContentLen,
      final String keyAlgo,
      final int keyLenBytes,
      final int value,
      final String dataKeyAlgo,
      final int dataKeyLen,
      boolean safeToCache,
      final String trailingSignatureAlgo,
      final int trailingSignatureLength,
      final String keyCommitmentAlgo,
      final int commitmentLength,
      final int commitmentNonceLength,
      final int suiteDataLength) {
    if ((messageFormatVersion & 0xFF) != messageFormatVersion) {
      throw new IllegalArgumentException("Invalid messageFormatVersion: " + messageFormatVersion);
    }
    // All non-null key commitment algs must be the same as the kdf alg
    if (keyCommitmentAlgo != null && !keyCommitmentAlgo.equals(dataKeyAlgo)) {
      throw new IllegalArgumentException(
          "Invalid keyCommitmentAlgo "
              + keyCommitmentAlgo
              + ". Must be equal to dataKeyAlgo "
              + dataKeyAlgo
              + ".");
    }
    messageFormatVersion_ = (byte) (messageFormatVersion & 0xFF);
    blockSizeBits_ = blockSizeBits;
    nonceLenBytes_ = (byte) nonceLenBytes;
    tagLenBytes_ = tagLenBytes;
    keyAlgo_ = keyAlgo;
    keyLenBytes_ = keyLenBytes;
    maxContentLen_ = maxContentLen;
    safeToCache_ = safeToCache;
    if (value > Short.MAX_VALUE || value < Short.MIN_VALUE) {
      throw new IllegalArgumentException("Invalid value " + value);
    }
    value_ = (short) value;
    dataKeyAlgo_ = dataKeyAlgo;
    dataKeyLen_ = dataKeyLen;
    trailingSigAlgo_ = trailingSignatureAlgo;
    if (trailingSignatureLength > Short.MAX_VALUE || trailingSignatureLength < 0) {
      throw new IllegalArgumentException("Invalid value " + trailingSignatureLength);
    }
    trailingSigLen_ = (short) trailingSignatureLength;
    keyCommitmentAlgo_ = keyCommitmentAlgo;
    commitmentLength_ = commitmentLength;
    commitmentNonceLength_ = commitmentNonceLength;
    suiteDataLength_ = suiteDataLength;
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
  @Deprecated
  public static CryptoAlgorithm deserialize(final short value) {
    return deserialize((byte) 1, value);
  }

  /**
   * Returns the CryptoAlgorithm object that matches the given value.
   *
   * @param value the value of the object
   * @return the CryptoAlgorithm object that matches the given value, null if no match is found.
   */
  public static CryptoAlgorithm deserialize(final byte messageFormatVersion, final short value) {
    return ID_MAPPING.get(fieldsToLookupKey(messageFormatVersion, value));
  }

  /** Returns the length of the message Id in the header for this algorithm. */
  public int getMessageIdLength() {
    // For now this is a derived value rather than stored explicitly
    switch (messageFormatVersion_) {
      case VERSION_1:
        return VERSION_1_MESSAGE_ID_LEN;
      case VERSION_2:
        return VERSION_2_MESSAGE_ID_LEN;
      default:
        throw new UnsupportedOperationException(
            "Support for version " + messageFormatVersion_ + " not yet built.");
    }
  }

  /**
   * Returns the header nonce to use with this algorithm. null indicates that the header nonce is
   * not a parameter of the algorithm, and is instead stored as part of the message header.
   */
  public byte[] getHeaderNonce() {
    // For now this is a derived value rather than stored explicitly
    switch (messageFormatVersion_) {
      case VERSION_1:
        return null;
      case VERSION_2:
        // V2 explicitly uses an IV of 0 in the header
        return new byte[nonceLenBytes_];
      default:
        throw new UnsupportedOperationException(
            "Support for version " + messageFormatVersion_ + " not yet built.");
    }
  }

  /** Returns the message format version associated with this algorithm suite. */
  public byte getMessageFormatVersion() {
    return messageFormatVersion_;
  }

  /** Returns the block size of this algorithm in bytes. */
  public int getBlockSize() {
    return blockSizeBits_ / 8;
  }

  /** Returns the nonce length used in this algorithm in bytes. */
  public byte getNonceLen() {
    return nonceLenBytes_;
  }

  /** Returns the tag length used in this algorithm in bytes. */
  public int getTagLen() {
    return tagLenBytes_;
  }

  /**
   * Returns the maximum content length in bytes that can be processed under a single data key in
   * this algorithm.
   */
  public long getMaxContentLen() {
    return maxContentLen_;
  }

  /** Returns the algorithm used for encrypting the plaintext data. */
  public String getKeyAlgo() {
    return keyAlgo_;
  }

  /** Returns the length of the key used in this algorithm in bytes. */
  public int getKeyLength() {
    return keyLenBytes_;
  }

  /** Returns the value used to encode this algorithm in the ciphertext. */
  public short getValue() {
    return value_;
  }

  /** Returns the algorithm associated with the data key. */
  public String getDataKeyAlgo() {
    return dataKeyAlgo_;
  }

  /** Returns the length of the data key in bytes. */
  public int getDataKeyLength() {
    return dataKeyLen_;
  }

  /** Returns the algorithm used to calculate the trailing signature */
  public String getTrailingSignatureAlgo() {
    return trailingSigAlgo_;
  }

  /**
   * Returns whether data keys used with this crypto algorithm can safely be cached and reused for a
   * different message. If this returns false, reuse of data keys is likely to result in severe
   * cryptographic weaknesses, potentially even with only a single such use.
   */
  public boolean isSafeToCache() {
    return safeToCache_;
  }

  /**
   * Returns the length of the trailing signature generated by this algorithm. The actual trailing
   * signature may be shorter than this.
   */
  public short getTrailingSignatureLength() {
    return trailingSigLen_;
  }

  public String getKeyCommitmentAlgo_() {
    return keyCommitmentAlgo_;
  }

  /**
   * Returns a derived value of whether a commitment value is generated with the key in order to
   * ensure key commitment.
   */
  public boolean isCommitting() {
    return keyCommitmentAlgo_ != null;
  }

  public int getCommitmentLength() {
    return commitmentLength_;
  }

  public int getCommitmentNonceLength() {
    return commitmentNonceLength_;
  }

  public int getSuiteDataLength() {
    return suiteDataLength_;
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
    switch (messageFormatVersion_) {
      case VERSION_1:
        return getNonCommittedEncryptionKey(dataKey, headers);
      case VERSION_2:
        return getCommittedEncryptionKey(dataKey, headers);
      default:
        throw new UnsupportedOperationException(
            "Support for message format version " + messageFormatVersion_ + " not yet built.");
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
