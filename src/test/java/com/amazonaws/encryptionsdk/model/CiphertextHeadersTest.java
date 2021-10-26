// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.model;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.EncryptionContextSerializer;
import com.amazonaws.encryptionsdk.internal.RandomBytesGenerator;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class CiphertextHeadersTest {
  final CryptoAlgorithm cryptoAlgo_ =
      CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
  final String keyProviderId_ = "None";
  final byte[] keyProviderInfo_ = "TestKeyID".getBytes();
  final byte version_ = cryptoAlgo_.getMessageFormatVersion();
  final byte invalidVersion_ = 0x00;
  final CiphertextType type_ = CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA;
  final int nonceLen_ = cryptoAlgo_.getNonceLen();
  final int tagLenBytes_ = cryptoAlgo_.getTagLen();
  final ContentType contentType_ = ContentType.FRAME;
  final int frameSize_ = AwsCrypto.getDefaultFrameSize();

  // A set of crypto algs that are representative of the different ciphertext header formats
  final List<CryptoAlgorithm> testAlgs =
      Arrays.asList(
          CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256);

  byte[] encryptedKey_ = RandomBytesGenerator.generate(cryptoAlgo_.getKeyLength());

  final KeyBlob keyBlob_ = new KeyBlob(keyProviderId_, keyProviderInfo_, encryptedKey_);

  byte[] headerNonce_ = RandomBytesGenerator.generate(nonceLen_);
  byte[] headerTag_ = RandomBytesGenerator.generate(tagLenBytes_);

  @Test
  public void serializeDeserialize() {
    int maxEncryptedDataKeys = 42;

    Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Test");

    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext, alg);

      final byte[] headerBytes = ciphertextHeaders.toByteArray();
      final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
      reconstructedHeaders.deserialize(headerBytes, 0, maxEncryptedDataKeys);
      final byte[] reconstructedHeaderBytes = reconstructedHeaders.toByteArray();

      assertEquals(reconstructedHeaders.getMaxEncryptedDataKeys(), maxEncryptedDataKeys);
      assertArrayEquals(headerBytes, reconstructedHeaderBytes);
    }
  }

  @Test
  public void serializeDeserializeDefaultMaxEncryptedDataKeys() {
    Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Test");

    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext, alg);

      final byte[] headerBytes = ciphertextHeaders.toByteArray();
      final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
      reconstructedHeaders.deserialize(headerBytes, 0);
      final byte[] reconstructedHeaderBytes = reconstructedHeaders.toByteArray();

      assertEquals(
          reconstructedHeaders.getMaxEncryptedDataKeys(),
          CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
      assertArrayEquals(headerBytes, reconstructedHeaderBytes);
    }
  }

  @Test
  public void serializeDeserializeStreaming() {
    Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext, alg);

      final byte[] headerBytes = ciphertextHeaders.toByteArray();
      final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();

      int totalParsedBytes = 0;
      int bytesToParseLen = 1;
      int bytesParsed;

      while (reconstructedHeaders.isComplete() == false) {
        final byte[] bytesToParse = new byte[bytesToParseLen];
        System.arraycopy(headerBytes, totalParsedBytes, bytesToParse, 0, bytesToParse.length);

        bytesParsed =
            reconstructedHeaders.deserialize(
                bytesToParse, 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
        if (bytesParsed == 0) {
          bytesToParseLen++;
        } else {
          totalParsedBytes += bytesParsed;
          bytesToParseLen = 1;
        }
      }

      final byte[] reconstructedHeaderBytes = reconstructedHeaders.toByteArray();

      assertArrayEquals(headerBytes, reconstructedHeaderBytes);
    }
  }

  @Test
  public void deserializeNull() {
    final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders();
    final int deserializedBytes =
        ciphertextHeaders.deserialize(null, 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);

    assertEquals(0, deserializedBytes);
  }

  @Test
  public void overlyLargeEncryptionContext() {
    final int size = Constants.UNSIGNED_SHORT_MAX_VAL + 1;
    final byte[] encContextBytes = RandomBytesGenerator.generate(size);
    for (CryptoAlgorithm alg : testAlgs) {
      assertThrows(AwsCryptoException.class, () -> createCiphertextHeaders(encContextBytes, alg));
    }
  }

  @Test
  public void serializeWithNullHeaderNonce() {
    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders =
          new CiphertextHeaders(
              type_,
              alg,
              new byte[0],
              Collections.singletonList(keyBlob_),
              contentType_,
              frameSize_);
      ciphertextHeaders.setHeaderTag(headerTag_);

      assertThrows(AwsCryptoException.class, () -> ciphertextHeaders.toByteArray());
    }
  }

  @Test
  public void serializeWithNullHeaderTag() {
    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders =
          new CiphertextHeaders(
              type_,
              alg,
              new byte[0],
              Collections.singletonList(keyBlob_),
              contentType_,
              frameSize_);
      ciphertextHeaders.setHeaderNonce(headerNonce_);

      assertThrows(AwsCryptoException.class, () -> ciphertextHeaders.toByteArray());
    }
  }

  @Test
  public void serializeWithNullSuiteData() {
    // Only applicable for V2 algorithms
    CryptoAlgorithm alg = CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    final CiphertextHeaders ciphertextHeaders =
        new CiphertextHeaders(
            type_, alg, new byte[0], Collections.singletonList(keyBlob_), contentType_, frameSize_);
    ciphertextHeaders.setHeaderTag(headerTag_);
    ciphertextHeaders.setHeaderNonce(headerNonce_);

    assertThrows(AwsCryptoException.class, () -> ciphertextHeaders.toByteArray());
  }

  /*
   * @Test
   * public void byteFormatCheck() {
   * testPlaintextKey_ = ByteFormatCheckValues.getPlaintextKey();
   * testKey_ = new SecretKeySpec(testPlaintextKey_,
   * cryptoAlgo_.getKeySpec());
   * encryptedKey_ = ByteFormatCheckValues.getEncryptedKey();
   * dataKey_ = new AWSKMSDataKey(testKey_, encryptedKey_);
   * headerNonce_ = ByteFormatCheckValues.getNonce();
   * headerTag_ = ByteFormatCheckValues.getTag();
   *
   * Map<String, String> encryptionContext = new HashMap<String, String>(1);
   * encryptionContext.put("ENC", "CiphertextHeader format check test");
   *
   * final CiphertextHeaders ciphertextHeaders =
   * createCiphertextHeaders(encryptionContext);
   * //NOTE: this test will fail because of the line below.
   * //That is, the message id is randomly generated in the ciphertext
   * headers.
   * messageId_ = ciphertextHeaders.getMessageId();
   * final byte[] ciphertextHeaderHash =
   * TestIOUtils.getSha256Hash(ciphertextHeaders.toByteArray());
   *
   * assertArrayEquals(ByteFormatCheckValues.getCiphertextHeaderHash(),
   * ciphertextHeaderHash);
   * }
   */

  private CiphertextHeaders createCiphertextHeaders(
      final byte[] encryptionContextBytes, CryptoAlgorithm cryptoAlg) {
    final CiphertextHeaders ciphertextHeaders =
        new CiphertextHeaders(
            type_,
            cryptoAlg,
            encryptionContextBytes,
            Collections.singletonList(keyBlob_),
            contentType_,
            frameSize_);

    ciphertextHeaders.setHeaderNonce(headerNonce_);
    ciphertextHeaders.setHeaderTag(headerTag_);

    if (cryptoAlg.getMessageFormatVersion() == 2) {
      ciphertextHeaders.setSuiteData(new byte[cryptoAlg.getSuiteDataLength()]);
    }

    return ciphertextHeaders;
  }

  private CiphertextHeaders createCiphertextHeaders(
      final Map<String, String> encryptionContext, CryptoAlgorithm cryptoAlg) {
    byte[] encryptionContextBytes = null;
    if (encryptionContext != null) {
      encryptionContextBytes = EncryptionContextSerializer.serialize(encryptionContext);
    }

    return createCiphertextHeaders(encryptionContextBytes, cryptoAlg);
  }

  @SuppressWarnings("deprecation")
  @Test
  public void legacyConstructCiphertextHeaders() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");
    final byte[] encryptionContextBytes = EncryptionContextSerializer.serialize(encryptionContext);

    final CiphertextHeaders ciphertextHeaders =
        new CiphertextHeaders(
            version_,
            type_,
            cryptoAlgo_,
            encryptionContextBytes,
            Collections.singletonList(keyBlob_),
            contentType_,
            frameSize_);

    ciphertextHeaders.setHeaderNonce(headerNonce_);
    ciphertextHeaders.setHeaderTag(headerTag_);
    assertNotNull(ciphertextHeaders);
  }

  @SuppressWarnings("deprecation")
  @Test(expected = IllegalArgumentException.class)
  public void legacyConstructCiphertextHeadersMismatchedVersion() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");
    final byte[] encryptionContextBytes = EncryptionContextSerializer.serialize(encryptionContext);

    final CiphertextHeaders ciphertextHeaders =
        new CiphertextHeaders(
            invalidVersion_,
            type_,
            cryptoAlgo_,
            encryptionContextBytes,
            Collections.singletonList(keyBlob_),
            contentType_,
            frameSize_);
  }

  @Test
  public void checkEncContextLen() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");
    final byte[] encryptionContextBytes = EncryptionContextSerializer.serialize(encryptionContext);
    final int encryptionContextLen = encryptionContextBytes.length;

    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext, alg);
      final byte[] headerBytes = ciphertextHeaders.toByteArray();

      final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
      reconstructedHeaders.deserialize(
          headerBytes, 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);

      assertEquals(encryptionContextLen, reconstructedHeaders.getEncryptionContextLen());
    }
  }

  @Test
  public void checkKeyBlobCount() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext, alg);
      final byte[] headerBytes = ciphertextHeaders.toByteArray();

      final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
      reconstructedHeaders.deserialize(
          headerBytes, 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);

      assertEquals(1, reconstructedHeaders.getEncryptedKeyBlobCount());
    }
  }

  @Test
  public void checkNullMessageId() {
    final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders();

    assertEquals(null, ciphertextHeaders.getMessageId());
  }

  @Test
  public void checkNullHeaderNonce() {
    final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders();

    assertEquals(null, ciphertextHeaders.getHeaderNonce());
  }

  @Test
  public void checkNullHeaderTag() {
    final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders();

    assertEquals(null, ciphertextHeaders.getHeaderTag());
  }

  private void readVersion(final ByteBuffer headerBuff) {
    headerBuff.get();
  }

  private void readType(final ByteBuffer headerBuff) {
    readVersion(headerBuff);
    headerBuff.get();
  }

  private void readToAlgoId(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    // Use the message format version to determine where the algorithm Id is in the
    // header and how to get to it.
    if (cryptoAlg.getMessageFormatVersion() == 1) {
      readType(headerBuff);
    } else {
      readVersion(headerBuff);
    }
  }

  private void readAlgoId(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    readToAlgoId(headerBuff, cryptoAlg);
    headerBuff.getShort();
  }

  private void readEncContext(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    readAlgoId(headerBuff, cryptoAlg);

    // pull out messageId to get to enc context len.
    final byte[] msgId = new byte[cryptoAlg.getMessageIdLength()];
    headerBuff.get(msgId);

    // pull out enc context to get to key count.
    final int encContextLen = headerBuff.getShort();
    final byte[] encContext = new byte[encContextLen];
    headerBuff.get(encContext);
  }

  private void readKeyBlob(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    readEncContext(headerBuff, cryptoAlg);

    headerBuff.getShort(); // get key count
    final short keyProviderIdLen = headerBuff.getShort();
    final byte[] keyProviderId = new byte[keyProviderIdLen];
    headerBuff.get(keyProviderId);
    final short keyProviderInfoLen = headerBuff.getShort();
    final byte[] keyProviderInfo = new byte[keyProviderInfoLen];
    headerBuff.get(keyProviderInfo);
    final short keyLen = headerBuff.getShort();
    final byte[] key = new byte[keyLen];
    headerBuff.get(key);
  }

  private void readToContentType(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    readKeyBlob(headerBuff, cryptoAlg);
  }

  private void readContentType(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    readToContentType(headerBuff, cryptoAlg);
    headerBuff.get();
  }

  private void readToReservedField(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    readContentType(headerBuff, cryptoAlg);
  }

  private void readReservedField(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    readToReservedField(headerBuff, cryptoAlg);
    headerBuff.getInt();
  }

  private void readToNonceLen(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    readReservedField(headerBuff, cryptoAlg);
  }

  private void readNonceLen(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    readToNonceLen(headerBuff, cryptoAlg);
    headerBuff.get();
  }

  private void readToFrameLen(final ByteBuffer headerBuff, final CryptoAlgorithm cryptoAlg) {
    // Use the message format version to determine where the frame length is in the
    // header and how to get to it.
    if (cryptoAlg.getMessageFormatVersion() == 1) {
      readNonceLen(headerBuff, cryptoAlg);
    } else {
      readContentType(headerBuff, cryptoAlg);
    }
  }

  @Test
  public void invalidVersion() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext, alg);
      final byte[] headerBytes = ciphertextHeaders.toByteArray();
      final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

      // set version to invalid type of 0.
      headerBuff.put((byte) 0);

      final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
      assertThrows(
          BadCiphertextException.class,
          "Invalid version",
          () ->
              reconstructedHeaders.deserialize(
                  headerBuff.array(), 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
    }
  }

  @Test
  public void invalidType() {
    // Only applicable for V1 algorithms
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");
    final CryptoAlgorithm cryptoAlgorithm = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;

    final CiphertextHeaders ciphertextHeaders =
        createCiphertextHeaders(encryptionContext, cryptoAlgorithm);
    final byte[] headerBytes = ciphertextHeaders.toByteArray();
    final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

    readVersion(headerBuff);

    // set type to invalid value of 0.
    headerBuff.put((byte) 0);

    final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
    assertThrows(
        BadCiphertextException.class,
        "Invalid ciphertext type",
        () ->
            reconstructedHeaders.deserialize(
                headerBuff.array(), 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
  }

  @Test
  public void invalidAlgoId() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext, alg);
      final byte[] headerBytes = ciphertextHeaders.toByteArray();
      final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

      readToAlgoId(headerBuff, alg);

      // set algoId to invalid value of 0.
      headerBuff.putShort((short) 0);

      final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
      assertThrows(
          BadCiphertextException.class,
          "Invalid algorithm identifier in ciphertext",
          () ->
              reconstructedHeaders.deserialize(
                  headerBuff.array(), 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
    }
  }

  @Test
  public void invalidContentType() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext, alg);
      final byte[] headerBytes = ciphertextHeaders.toByteArray();
      final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

      readToContentType(headerBuff, alg);

      // set content type to an invalid value
      headerBuff.put((byte) 10);

      final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
      assertThrows(
          BadCiphertextException.class,
          "Invalid content type in ciphertext.",
          () ->
              reconstructedHeaders.deserialize(
                  headerBuff.array(), 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
    }
  }

  @Test
  public void invalidReservedFieldLen() {
    // Only applicable for V1 algorithms
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");
    final CryptoAlgorithm cryptoAlgorithm = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;

    final CiphertextHeaders ciphertextHeaders =
        createCiphertextHeaders(encryptionContext, cryptoAlgorithm);
    final byte[] headerBytes = ciphertextHeaders.toByteArray();
    final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

    readToReservedField(headerBuff, cryptoAlgorithm);

    // set reserved field to an invalid value
    headerBuff.putInt(-1);

    final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
    assertThrows(
        BadCiphertextException.class,
        "Invalid value for reserved field in ciphertext",
        () ->
            reconstructedHeaders.deserialize(
                headerBuff.array(), 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
  }

  @Test
  public void invalidNonceLen() {
    // Only applicable for V1 algorithms
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");
    final CryptoAlgorithm cryptoAlgorithm = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;

    final CiphertextHeaders ciphertextHeaders =
        createCiphertextHeaders(encryptionContext, cryptoAlgorithm);
    final byte[] headerBytes = ciphertextHeaders.toByteArray();
    final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

    readToNonceLen(headerBuff, cryptoAlgorithm);

    // set nonce len to an invalid value
    headerBuff.put((byte) -1);

    final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
    assertThrows(
        BadCiphertextException.class,
        "Invalid nonce length in ciphertext",
        () ->
            reconstructedHeaders.deserialize(
                headerBuff.array(), 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
  }

  @Test
  public void invalidFrameLength() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

    for (CryptoAlgorithm alg : testAlgs) {
      final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext, alg);
      final byte[] headerBytes = ciphertextHeaders.toByteArray();
      final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

      readToFrameLen(headerBuff, alg);

      // set frame len to an invalid value
      headerBuff.putInt(-1);

      final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
      assertThrows(
          BadCiphertextException.class,
          "Invalid frame length in ciphertext",
          () ->
              reconstructedHeaders.deserialize(
                  headerBuff.array(), 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
    }
  }
}
