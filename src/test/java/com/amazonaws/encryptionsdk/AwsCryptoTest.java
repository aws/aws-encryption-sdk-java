// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static com.amazonaws.encryptionsdk.FastTestsOnlySuite.isFastTestSuiteActive;
import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static java.util.Collections.singletonMap;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.StaticMasterKey;
import com.amazonaws.encryptionsdk.internal.TestIOUtils;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.model.CiphertextType;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.amazonaws.util.IOUtils;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.Before;
import org.junit.Test;

public class AwsCryptoTest {
  private StaticMasterKey masterKeyProvider;
  private AwsCrypto encryptionClient_;
  private AwsCrypto noMaxEdksClient_;
  private AwsCrypto maxEdksClient_;
  private static final CommitmentPolicy commitmentPolicy = TestUtils.DEFAULT_TEST_COMMITMENT_POLICY;
  private static final int MESSAGE_FORMAT_MAX_EDKS = (1 << 16) - 1;

  @Before
  public void init() {
    masterKeyProvider = spy(new StaticMasterKey("testmaterial"));

    encryptionClient_ =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();
    encryptionClient_.setEncryptionAlgorithm(
        CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256);

    noMaxEdksClient_ =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256)
            .build();
    maxEdksClient_ =
        AwsCrypto.builder()
            .withMaxEncryptedDataKeys(3)
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256)
            .build();
  }

  private void doEncryptDecrypt(
      final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
    final byte[] plaintextBytes = new byte[byteSize];

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

    encryptionClient_.setEncryptionAlgorithm(cryptoAlg);
    encryptionClient_.setEncryptionFrameSize(frameSize);

    final byte[] cipherText =
        encryptionClient_
            .encryptData(masterKeyProvider, plaintextBytes, encryptionContext)
            .getResult();
    final byte[] decryptedText =
        encryptionClient_.decryptData(masterKeyProvider, cipherText).getResult();

    assertArrayEquals("Bad encrypt/decrypt for " + cryptoAlg, plaintextBytes, decryptedText);
  }

  private void doTamperedEncryptDecrypt(
      final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
    final byte[] plaintextBytes = new byte[byteSize];

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

    encryptionClient_.setEncryptionAlgorithm(cryptoAlg);
    encryptionClient_.setEncryptionFrameSize(frameSize);

    final byte[] cipherText =
        encryptionClient_
            .encryptData(masterKeyProvider, plaintextBytes, encryptionContext)
            .getResult();
    cipherText[cipherText.length - 2] ^= (byte) 0xff;
    try {
      encryptionClient_.decryptData(masterKeyProvider, cipherText).getResult();
      fail("Expected BadCiphertextException");
    } catch (final BadCiphertextException ex) {
      // Expected exception
    }
  }

  private void doTruncatedEncryptDecrypt(
      final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
    final byte[] plaintextBytes = new byte[byteSize];

    final Map<String, String> encryptionContext = new HashMap<>(1);
    encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

    encryptionClient_.setEncryptionAlgorithm(cryptoAlg);
    encryptionClient_.setEncryptionFrameSize(frameSize);

    final byte[] cipherText =
        encryptionClient_
            .encryptData(masterKeyProvider, plaintextBytes, encryptionContext)
            .getResult();
    final byte[] truncatedCipherText = Arrays.copyOf(cipherText, cipherText.length - 1);
    try {
      encryptionClient_.decryptData(masterKeyProvider, truncatedCipherText).getResult();
      fail("Expected BadCiphertextException");
    } catch (final BadCiphertextException ex) {
      // Expected exception
    }
  }

  private void doEncryptDecryptWithParsedCiphertext(final int byteSize, final int frameSize) {
    final byte[] plaintextBytes = new byte[byteSize];

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

    encryptionClient_.setEncryptionFrameSize(frameSize);

    final byte[] cipherText =
        encryptionClient_
            .encryptData(masterKeyProvider, plaintextBytes, encryptionContext)
            .getResult();
    ParsedCiphertext pCt = new ParsedCiphertext(cipherText);
    assertEquals(encryptionClient_.getEncryptionAlgorithm(), pCt.getCryptoAlgoId());
    assertEquals(CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA, pCt.getType());
    assertEquals(1, pCt.getEncryptedKeyBlobCount());
    assertEquals(pCt.getEncryptedKeyBlobCount(), pCt.getEncryptedKeyBlobs().size());
    assertEquals(
        masterKeyProvider.getProviderId(), pCt.getEncryptedKeyBlobs().get(0).getProviderId());
    for (Map.Entry<String, String> e : encryptionContext.entrySet()) {
      assertEquals(e.getValue(), pCt.getEncryptionContextMap().get(e.getKey()));
    }

    final byte[] decryptedText = encryptionClient_.decryptData(masterKeyProvider, pCt).getResult();

    assertArrayEquals(plaintextBytes, decryptedText);
  }

  @Test
  public void encryptDecrypt() {
    for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
      // Only test with crypto algs without commitment, since those
      // are the only ones we can encrypt with
      if (cryptoAlg.getMessageFormatVersion() != 1) {
        continue;
      }

      final int[] frameSizeToTest = TestUtils.getFrameSizesToTest(cryptoAlg);

      for (int i = 0; i < frameSizeToTest.length; i++) {
        final int frameSize = frameSizeToTest[i];
        int[] bytesToTest = {
          0,
          1,
          frameSize - 1,
          frameSize,
          frameSize + 1,
          (int) (frameSize * 1.5),
          frameSize * 2,
          1000000
        };

        for (int j = 0; j < bytesToTest.length; j++) {
          final int byteSize = bytesToTest[j];

          if (byteSize > 500_000 && isFastTestSuiteActive()) {
            continue;
          }

          if (byteSize >= 0) {
            doEncryptDecrypt(cryptoAlg, byteSize, frameSize);
          }
        }
      }
    }
  }

  @SuppressWarnings("deprecation")
  @Test
  public void legacyConstructorEncryptDecrypt() {
    final byte[] plaintextBytes = new byte[100];

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "legacy constructor encrypt-decrypt test");

    AwsCrypto client = new AwsCrypto();

    client.setEncryptionAlgorithm(TestUtils.DEFAULT_TEST_CRYPTO_ALG);
    client.setEncryptionFrameSize(100);

    final byte[] cipherText =
        client.encryptData(masterKeyProvider, plaintextBytes, encryptionContext).getResult();
    final byte[] decryptedText = client.decryptData(masterKeyProvider, cipherText).getResult();

    assertArrayEquals("Bad encrypt/decrypt for legacy constructor", plaintextBytes, decryptedText);
  }

  @SuppressWarnings("deprecation")
  @Test
  public void legacyConstructorLegacyCMMEncryptDecrypt() {
    final byte[] plaintextBytes = new byte[100];

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "legacy constructor encrypt-decrypt test");
    final DefaultCryptoMaterialsManager cmm = new DefaultCryptoMaterialsManager(masterKeyProvider);

    AwsCrypto client = new AwsCrypto();

    client.setEncryptionAlgorithm(TestUtils.DEFAULT_TEST_CRYPTO_ALG);
    client.setEncryptionFrameSize(100);

    final byte[] cipherText =
        client.encryptData(cmm, plaintextBytes, encryptionContext).getResult();
    final byte[] decryptedText = client.decryptData(cmm, cipherText).getResult();

    assertArrayEquals(
        "Bad encrypt/decrypt for legacy constructor with legacy cmm",
        plaintextBytes,
        decryptedText);
  }

  @SuppressWarnings("deprecation")
  @Test
  public void legacyConstructorEncryptDecryptInterop() {
    final byte[] plaintextBytes = new byte[100];

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "legacy constructor encrypt-decrypt test");

    final DefaultCryptoMaterialsManager legacy =
        new DefaultCryptoMaterialsManager(masterKeyProvider);

    AwsCrypto legacyClient = new AwsCrypto();

    legacyClient.setEncryptionAlgorithm(TestUtils.DEFAULT_TEST_CRYPTO_ALG);
    legacyClient.setEncryptionFrameSize(100);

    encryptionClient_.setEncryptionAlgorithm(TestUtils.DEFAULT_TEST_CRYPTO_ALG);
    encryptionClient_.setEncryptionFrameSize(100);

    // Test the legacy constructed message can be decrypted by the default client
    final byte[] cipherText =
        legacyClient.encryptData(masterKeyProvider, plaintextBytes, encryptionContext).getResult();
    final byte[] decryptedText =
        encryptionClient_.decryptData(masterKeyProvider, cipherText).getResult();
    assertArrayEquals("Bad encrypt/decrypt for legacy interop", plaintextBytes, decryptedText);

    // Test the default client constructed message can be decrypted by the legacy client
    final byte[] cipherText2 =
        encryptionClient_
            .encryptData(masterKeyProvider, plaintextBytes, encryptionContext)
            .getResult();
    final byte[] decryptedText2 =
        legacyClient.decryptData(masterKeyProvider, cipherText2).getResult();
    assertArrayEquals("Bad encrypt/decrypt for legacy interop", plaintextBytes, decryptedText2);

    // Now interop test using a legacy constructed Default Crypto Materials Manager
    final DefaultCryptoMaterialsManager cmm = new DefaultCryptoMaterialsManager(masterKeyProvider);

    // Test the default client constructed message can be decrypted by the legacy client with legacy
    // cmm
    final byte[] cipherText3 =
        encryptionClient_.encryptData(cmm, plaintextBytes, encryptionContext).getResult();
    final byte[] decryptedText3 = legacyClient.decryptData(cmm, cipherText3).getResult();
    assertArrayEquals("Bad encrypt/decrypt for legacy interop", plaintextBytes, decryptedText3);

    // Test the legacy constructed message can be decrypted by the default client
    final byte[] cipherText4 =
        legacyClient.encryptData(masterKeyProvider, plaintextBytes, encryptionContext).getResult();
    final byte[] decryptedText4 =
        encryptionClient_.decryptData(masterKeyProvider, cipherText4).getResult();
    assertArrayEquals("Bad encrypt/decrypt for legacy interop", plaintextBytes, decryptedText4);
  }

  @Test
  public void encryptDecryptWithBadSignature() {
    for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
      // Only test with crypto algs without commitment, since those
      // are the only ones we can encrypt with
      if (cryptoAlg.getMessageFormatVersion() != 1) {
        continue;
      }

      if (cryptoAlg.getTrailingSignatureAlgo() == null) {
        continue;
      }
      final int[] frameSizeToTest = TestUtils.getFrameSizesToTest(cryptoAlg);

      for (int i = 0; i < frameSizeToTest.length; i++) {
        final int frameSize = frameSizeToTest[i];
        int[] bytesToTest = {
          0,
          1,
          frameSize - 1,
          frameSize,
          frameSize + 1,
          (int) (frameSize * 1.5),
          frameSize * 2,
          1000000
        };

        for (int j = 0; j < bytesToTest.length; j++) {
          final int byteSize = bytesToTest[j];

          if (byteSize > 500_000 && isFastTestSuiteActive()) {
            continue;
          }

          if (byteSize >= 0) {
            doTamperedEncryptDecrypt(cryptoAlg, byteSize, frameSize);
          }
        }
      }
    }
  }

  @Test
  public void encryptDecryptWithTruncatedCiphertext() {
    for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
      // Only test with crypto algs without commitment, since those
      // are the only ones we can encrypt with
      if (cryptoAlg.getMessageFormatVersion() != 1) {
        continue;
      }

      final int[] frameSizeToTest = TestUtils.getFrameSizesToTest(cryptoAlg);

      for (int i = 0; i < frameSizeToTest.length; i++) {
        final int frameSize = frameSizeToTest[i];
        int[] bytesToTest = {
          0,
          1,
          frameSize - 1,
          frameSize,
          frameSize + 1,
          (int) (frameSize * 1.5),
          frameSize * 2,
          1000000
        };

        for (int j = 0; j < bytesToTest.length; j++) {
          final int byteSize = bytesToTest[j];

          if (byteSize > 500_000) {
            continue;
          }

          if (byteSize >= 0) {
            doTruncatedEncryptDecrypt(cryptoAlg, byteSize, frameSize);
          }
        }
      }
    }
  }

  @Test
  public void encryptDecryptWithParsedCiphertext() {
    for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
      final int[] frameSizeToTest = TestUtils.getFrameSizesToTest(cryptoAlg);

      for (int i = 0; i < frameSizeToTest.length; i++) {
        final int frameSize = frameSizeToTest[i];
        int[] bytesToTest = {
          0,
          1,
          frameSize - 1,
          frameSize,
          frameSize + 1,
          (int) (frameSize * 1.5),
          frameSize * 2,
          1000000
        };

        for (int j = 0; j < bytesToTest.length; j++) {
          final int byteSize = bytesToTest[j];

          if (byteSize > 500_000 && isFastTestSuiteActive()) {
            continue;
          }

          if (byteSize >= 0) {
            doEncryptDecryptWithParsedCiphertext(byteSize, frameSize);
          }
        }
      }
    }
  }

  @Test
  public void encryptDecryptWithCustomManager() throws Exception {
    boolean[] didDecrypt = new boolean[] {false};

    CryptoMaterialsManager manager =
        new CryptoMaterialsManager() {
          @Override
          public EncryptionMaterials getMaterialsForEncrypt(EncryptionMaterialsRequest request) {
            request = request.toBuilder().setContext(singletonMap("foo", "bar")).build();

            EncryptionMaterials encryptionMaterials =
                new DefaultCryptoMaterialsManager(masterKeyProvider)
                    .getMaterialsForEncrypt(request);

            return encryptionMaterials;
          }

          @Override
          public DecryptionMaterials decryptMaterials(DecryptionMaterialsRequest request) {
            didDecrypt[0] = true;
            return new DefaultCryptoMaterialsManager(masterKeyProvider).decryptMaterials(request);
          }
        };

    byte[] plaintext = new byte[100];
    CryptoResult<byte[], ?> ciphertext = encryptionClient_.encryptData(manager, plaintext);
    assertEquals("bar", ciphertext.getEncryptionContext().get("foo"));

    // TODO decrypt
    assertFalse(didDecrypt[0]);
    CryptoResult<byte[], ?> plaintextResult =
        encryptionClient_.decryptData(manager, ciphertext.getResult());
    assertArrayEquals(plaintext, plaintextResult.getResult());
    assertTrue(didDecrypt[0]);
  }

  @Test
  public void whenCustomCMMIgnoresAlgorithm_throws() throws Exception {
    boolean[] didDecrypt = new boolean[] {false};

    CryptoMaterialsManager manager =
        new CryptoMaterialsManager() {
          @Override
          public EncryptionMaterials getMaterialsForEncrypt(EncryptionMaterialsRequest request) {
            request = request.toBuilder().setRequestedAlgorithm(null).build();

            EncryptionMaterials encryptionMaterials =
                new DefaultCryptoMaterialsManager(masterKeyProvider)
                    .getMaterialsForEncrypt(request);

            return encryptionMaterials;
          }

          @Override
          public DecryptionMaterials decryptMaterials(DecryptionMaterialsRequest request) {
            didDecrypt[0] = true;
            return new DefaultCryptoMaterialsManager(masterKeyProvider).decryptMaterials(request);
          }
        };

    encryptionClient_.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_NO_KDF);

    byte[] plaintext = new byte[100];
    assertThrows(AwsCryptoException.class, () -> encryptionClient_.encryptData(manager, plaintext));
    assertThrows(
        AwsCryptoException.class, () -> encryptionClient_.estimateCiphertextSize(manager, 12345));
    assertThrows(
        AwsCryptoException.class,
        () ->
            encryptionClient_
                .createEncryptingStream(manager, new ByteArrayOutputStream())
                .write(0));
    assertThrows(
        AwsCryptoException.class,
        () ->
            encryptionClient_
                .createEncryptingStream(manager, new ByteArrayInputStream(new byte[1024 * 1024]))
                .read());
  }

  @Test
  public void whenCustomCMMUsesCommittingAlgorithmWithForbidPolicy_throws() throws Exception {
    CryptoMaterialsManager manager =
        new CryptoMaterialsManager() {
          @Override
          public EncryptionMaterials getMaterialsForEncrypt(EncryptionMaterialsRequest request) {
            EncryptionMaterials encryptionMaterials =
                new DefaultCryptoMaterialsManager(masterKeyProvider)
                    .getMaterialsForEncrypt(request);

            return encryptionMaterials.toBuilder()
                .setAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384)
                .build();
          }

          @Override
          public DecryptionMaterials decryptMaterials(DecryptionMaterialsRequest request) {
            return new DefaultCryptoMaterialsManager(masterKeyProvider).decryptMaterials(request);
          }
        };

    // create client with null encryption algorithm and ForbidEncrypt policy
    final AwsCrypto client =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();

    byte[] plaintext = new byte[100];
    assertThrows(AwsCryptoException.class, () -> client.encryptData(manager, plaintext));
    assertThrows(AwsCryptoException.class, () -> client.estimateCiphertextSize(manager, 12345));
    assertThrows(
        AwsCryptoException.class,
        () -> client.createEncryptingStream(manager, new ByteArrayOutputStream()).write(0));
    assertThrows(
        AwsCryptoException.class,
        () ->
            client
                .createEncryptingStream(manager, new ByteArrayInputStream(new byte[1024 * 1024]))
                .read());
  }

  @Test
  public void whenDecrypting_invokesMKPOnce() throws Exception {
    byte[] data = encryptionClient_.encryptData(masterKeyProvider, new byte[1]).getResult();

    reset(masterKeyProvider);

    encryptionClient_.decryptData(masterKeyProvider, data);

    verify(masterKeyProvider, times(1)).decryptDataKey(any(), any(), any());
  }

  private void doEstimateCiphertextSize(
      final CryptoAlgorithm cryptoAlg, final int inLen, final int frameSize) {
    final byte[] plaintext = TestIOUtils.generateRandomPlaintext(inLen);

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "Ciphertext size estimation test with " + inLen);

    encryptionClient_.setEncryptionAlgorithm(cryptoAlg);
    encryptionClient_.setEncryptionFrameSize(frameSize);

    final long estimatedCiphertextSize =
        encryptionClient_.estimateCiphertextSize(masterKeyProvider, inLen, encryptionContext);
    final byte[] cipherText =
        encryptionClient_.encryptData(masterKeyProvider, plaintext, encryptionContext).getResult();

    // The estimate should be close (within 16 bytes) and never less than reality
    final String errMsg =
        "Bad estimation for "
            + cryptoAlg
            + " expected: <"
            + estimatedCiphertextSize
            + "> but was: <"
            + cipherText.length
            + ">";
    assertTrue(errMsg, estimatedCiphertextSize - cipherText.length >= 0);
    assertTrue(errMsg, estimatedCiphertextSize - cipherText.length <= 16);
  }

  @Test
  public void estimateCiphertextSize() {
    for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
      // Only test with crypto algs without commitment, since those
      // are the only ones we can encrypt with
      if (cryptoAlg.getMessageFormatVersion() != 1) {
        continue;
      }

      final int[] frameSizeToTest = TestUtils.getFrameSizesToTest(cryptoAlg);

      for (int i = 0; i < frameSizeToTest.length; i++) {
        final int frameSize = frameSizeToTest[i];
        int[] bytesToTest = {
          0,
          1,
          frameSize - 1,
          frameSize,
          frameSize + 1,
          (int) (frameSize * 1.5),
          frameSize * 2,
          1000000
        };

        for (int j = 0; j < bytesToTest.length; j++) {
          final int byteSize = bytesToTest[j];

          if (byteSize > 500_000 && isFastTestSuiteActive()) {
            continue;
          }

          if (byteSize >= 0) {
            doEstimateCiphertextSize(cryptoAlg, byteSize, frameSize);
          }
        }
      }
    }
  }

  @Test
  public void estimateCiphertextSizeWithoutEncContext() {
    final int inLen = 1000000;
    final byte[] plaintext = TestIOUtils.generateRandomPlaintext(inLen);

    encryptionClient_.setEncryptionFrameSize(AwsCrypto.getDefaultFrameSize());

    final long estimatedCiphertextSize =
        encryptionClient_.estimateCiphertextSize(masterKeyProvider, inLen);
    final byte[] cipherText =
        encryptionClient_.encryptData(masterKeyProvider, plaintext).getResult();

    final String errMsg =
        "Bad estimation expected: <"
            + estimatedCiphertextSize
            + "> but was: <"
            + cipherText.length
            + ">";
    assertTrue(errMsg, estimatedCiphertextSize - cipherText.length >= 0);
    assertTrue(errMsg, estimatedCiphertextSize - cipherText.length <= 16);
  }

  @Test
  public void estimateCiphertextSize_usesCachedKeys() throws Exception {
    // Make sure estimateCiphertextSize works with cached CMMs
    CryptoMaterialsManager cmm = spy(new DefaultCryptoMaterialsManager(masterKeyProvider));

    CachingCryptoMaterialsManager cache =
        CachingCryptoMaterialsManager.newBuilder()
            .withBackingMaterialsManager(cmm)
            .withMaxAge(Long.MAX_VALUE, TimeUnit.SECONDS)
            .withCache(new LocalCryptoMaterialsCache(1))
            .withMessageUseLimit(9999)
            .withByteUseLimit(501)
            .build();

    // These estimates should be cached, and should not consume any bytes from the byte use limit.
    encryptionClient_.estimateCiphertextSize(cache, 500, new HashMap<>());
    encryptionClient_.estimateCiphertextSize(cache, 500, new HashMap<>());

    encryptionClient_.encryptData(cache, new byte[500]);

    verify(cmm, times(1)).getMaterialsForEncrypt(any());
  }

  @Test
  public void encryptDecryptWithoutEncContext() {
    final int ptSize = 1000000; // 1MB
    final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

    final byte[] cipherText =
        encryptionClient_.encryptData(masterKeyProvider, plaintextBytes).getResult();
    final byte[] decryptedText =
        encryptionClient_.decryptData(masterKeyProvider, cipherText).getResult();

    assertArrayEquals(plaintextBytes, decryptedText);
  }

  @Test
  public void encryptDecryptString() {
    final int ptSize = 1000000; // 1MB
    final String plaintextString = TestIOUtils.generateRandomString(ptSize);

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "Test Encryption Context");

    final String ciphertext =
        encryptionClient_
            .encryptString(masterKeyProvider, plaintextString, encryptionContext)
            .getResult();
    final String decryptedText =
        encryptionClient_.decryptString(masterKeyProvider, ciphertext).getResult();

    assertEquals(plaintextString, decryptedText);
  }

  @Test
  public void encryptDecryptStringWithoutEncContext() {
    final int ptSize = 1000000; // 1MB
    final String plaintextString = TestIOUtils.generateRandomString(ptSize);

    final String cipherText =
        encryptionClient_.encryptString(masterKeyProvider, plaintextString).getResult();
    final String decryptedText =
        encryptionClient_.decryptString(masterKeyProvider, cipherText).getResult();

    assertEquals(plaintextString, decryptedText);
  }

  @Test
  public void encryptBytesDecryptString() {
    final int ptSize = 1000000; // 1MB
    final String plaintext = TestIOUtils.generateRandomString(ptSize);

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "Test Encryption Context");

    final byte[] cipherText =
        encryptionClient_
            .encryptData(
                masterKeyProvider, plaintext.getBytes(StandardCharsets.UTF_8), encryptionContext)
            .getResult();
    final String decryptedText =
        encryptionClient_
            .decryptString(masterKeyProvider, Utils.encodeBase64String(cipherText))
            .getResult();

    assertEquals(plaintext, decryptedText);
  }

  @Test
  public void encryptStringDecryptBytes() {
    final int ptSize = 1000000; // 1MB
    final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);
    final String plaintextString = new String(plaintextBytes, StandardCharsets.UTF_8);

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "Test Encryption Context");

    final String ciphertext =
        encryptionClient_
            .encryptString(masterKeyProvider, plaintextString, encryptionContext)
            .getResult();
    final byte[] decryptedText =
        encryptionClient_
            .decryptData(masterKeyProvider, Utils.decodeBase64String(ciphertext))
            .getResult();

    assertArrayEquals(plaintextString.getBytes(StandardCharsets.UTF_8), decryptedText);
  }

  @Test
  public void emptyEncryptionContext() {
    final int ptSize = 1000000; // 1MB
    final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

    final Map<String, String> encryptionContext = new HashMap<String, String>(0);

    final byte[] cipherText =
        encryptionClient_
            .encryptData(masterKeyProvider, plaintextBytes, encryptionContext)
            .getResult();
    final byte[] decryptedText =
        encryptionClient_.decryptData(masterKeyProvider, cipherText).getResult();

    assertArrayEquals(plaintextBytes, decryptedText);
  }

  @Test
  public void decryptMessageWithKeyCommitment() {
    final byte[] cipherText = Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64);
    JceMasterKey masterKey = TestUtils.messageWithCommitKeyMasterKey;
    final CryptoResult decryptedText = encryptionClient_.decryptData(masterKey, cipherText);

    assertEquals(decryptedText.getCryptoAlgorithm(), TestUtils.messageWithCommitKeyCryptoAlgorithm);
    assertArrayEquals(
        decryptedText.getHeaders().getMessageId(),
        Utils.decodeBase64String(TestUtils.messageWithCommitKeyMessageIdBase64));
    assertArrayEquals(
        decryptedText.getHeaders().getSuiteData(),
        Utils.decodeBase64String(TestUtils.messageWithCommitKeyCommitmentBase64));
    assertArrayEquals(
        (byte[]) decryptedText.getResult(),
        TestUtils.messageWithCommitKeyExpectedResult.getBytes());
  }

  @Test
  public void decryptMessageWithInvalidKeyCommitment() {
    final byte[] cipherText = Utils.decodeBase64String(TestUtils.invalidMessageWithCommitKeyBase64);
    JceMasterKey masterKey = TestUtils.invalidMessageWithCommitKeyMasterKey;
    assertThrows(
        BadCiphertextException.class,
        "Key commitment validation failed. Key identity does not "
            + "match the identity asserted in the message. Halting processing of this message.",
        () -> encryptionClient_.decryptData(masterKey, cipherText));
  }

  // Test that all the parameters that aren't allowed to be null (i.e. all of them) result in
  // immediate NPEs if
  // invoked with null args
  @Test
  public void assertNullChecks() throws Exception {
    byte[] buf = new byte[1];
    HashMap<String, String> context = new HashMap<>();
    MasterKeyProvider provider = masterKeyProvider;
    CryptoMaterialsManager cmm = new DefaultCryptoMaterialsManager(masterKeyProvider);
    InputStream is = new ByteArrayInputStream(new byte[0]);
    OutputStream os = new ByteArrayOutputStream();

    byte[] ciphertext = encryptionClient_.encryptData(cmm, buf).getResult();
    String stringCiphertext = encryptionClient_.encryptString(cmm, "hello, world").getResult();

    TestUtils.assertNullChecks(
        encryptionClient_,
        "estimateCiphertextSize",
        MasterKeyProvider.class,
        provider,
        Integer.TYPE,
        42,
        Map.class,
        context);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "estimateCiphertextSize",
        CryptoMaterialsManager.class,
        cmm,
        Integer.TYPE,
        42,
        Map.class,
        context);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "estimateCiphertextSize",
        MasterKeyProvider.class,
        provider,
        Integer.TYPE,
        42);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "estimateCiphertextSize",
        CryptoMaterialsManager.class,
        cmm,
        Integer.TYPE,
        42);

    TestUtils.assertNullChecks(
        encryptionClient_,
        "encryptData",
        MasterKeyProvider.class,
        provider,
        byte[].class,
        buf,
        Map.class,
        context);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "encryptData",
        CryptoMaterialsManager.class,
        cmm,
        byte[].class,
        buf,
        Map.class,
        context);
    TestUtils.assertNullChecks(
        encryptionClient_, "encryptData", MasterKeyProvider.class, provider, byte[].class, buf);
    TestUtils.assertNullChecks(
        encryptionClient_, "encryptData", CryptoMaterialsManager.class, cmm, byte[].class, buf);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "encryptString",
        MasterKeyProvider.class,
        provider,
        String.class,
        "",
        Map.class,
        context);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "encryptString",
        CryptoMaterialsManager.class,
        cmm,
        String.class,
        "",
        Map.class,
        context);
    TestUtils.assertNullChecks(
        encryptionClient_, "encryptString", MasterKeyProvider.class, provider, String.class, "");
    TestUtils.assertNullChecks(
        encryptionClient_, "encryptString", CryptoMaterialsManager.class, cmm, String.class, "");

    TestUtils.assertNullChecks(
        encryptionClient_,
        "decryptData",
        MasterKeyProvider.class,
        provider,
        byte[].class,
        ciphertext);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "decryptData",
        CryptoMaterialsManager.class,
        cmm,
        byte[].class,
        ciphertext);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "decryptData",
        MasterKeyProvider.class,
        provider,
        ParsedCiphertext.class,
        new ParsedCiphertext(ciphertext));
    TestUtils.assertNullChecks(
        encryptionClient_,
        "decryptData",
        CryptoMaterialsManager.class,
        cmm,
        ParsedCiphertext.class,
        new ParsedCiphertext(ciphertext));
    TestUtils.assertNullChecks(
        encryptionClient_,
        "decryptString",
        MasterKeyProvider.class,
        provider,
        String.class,
        stringCiphertext);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "decryptString",
        CryptoMaterialsManager.class,
        cmm,
        String.class,
        stringCiphertext);

    TestUtils.assertNullChecks(
        encryptionClient_,
        "createEncryptingStream",
        MasterKeyProvider.class,
        provider,
        OutputStream.class,
        os,
        Map.class,
        context);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "createEncryptingStream",
        CryptoMaterialsManager.class,
        cmm,
        OutputStream.class,
        os,
        Map.class,
        context);

    TestUtils.assertNullChecks(
        encryptionClient_,
        "createEncryptingStream",
        MasterKeyProvider.class,
        provider,
        OutputStream.class,
        os);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "createEncryptingStream",
        CryptoMaterialsManager.class,
        cmm,
        OutputStream.class,
        os);

    TestUtils.assertNullChecks(
        encryptionClient_,
        "createEncryptingStream",
        MasterKeyProvider.class,
        provider,
        InputStream.class,
        is,
        Map.class,
        context);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "createEncryptingStream",
        CryptoMaterialsManager.class,
        cmm,
        InputStream.class,
        is,
        Map.class,
        context);

    TestUtils.assertNullChecks(
        encryptionClient_,
        "createEncryptingStream",
        MasterKeyProvider.class,
        provider,
        InputStream.class,
        is);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "createEncryptingStream",
        CryptoMaterialsManager.class,
        cmm,
        InputStream.class,
        is);

    TestUtils.assertNullChecks(
        encryptionClient_,
        "createDecryptingStream",
        MasterKeyProvider.class,
        provider,
        OutputStream.class,
        os);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "createDecryptingStream",
        CryptoMaterialsManager.class,
        cmm,
        OutputStream.class,
        os);

    TestUtils.assertNullChecks(
        encryptionClient_,
        "createDecryptingStream",
        MasterKeyProvider.class,
        provider,
        InputStream.class,
        is);
    TestUtils.assertNullChecks(
        encryptionClient_,
        "createDecryptingStream",
        CryptoMaterialsManager.class,
        cmm,
        InputStream.class,
        is);
  }

  @Test
  public void setValidFrameSize() throws IOException {
    final int setFrameSize = TestUtils.DEFAULT_TEST_CRYPTO_ALG.getBlockSize() * 2;
    encryptionClient_.setEncryptionFrameSize(setFrameSize);

    final int getFrameSize = encryptionClient_.getEncryptionFrameSize();

    assertEquals(setFrameSize, getFrameSize);
  }

  @Test
  public void unalignedFrameSizesAreAccepted() throws IOException {
    final int frameSize = TestUtils.DEFAULT_TEST_CRYPTO_ALG.getBlockSize() - 1;
    encryptionClient_.setEncryptionFrameSize(frameSize);

    assertEquals(frameSize, encryptionClient_.getEncryptionFrameSize());
  }

  @Test(expected = IllegalArgumentException.class)
  public void setNegativeFrameSize() throws IOException {
    encryptionClient_.setEncryptionFrameSize(-1);
  }

  @Test
  public void setCryptoAlgorithm() throws IOException {
    final CryptoAlgorithm setCryptoAlgorithm = CryptoAlgorithm.ALG_AES_192_GCM_IV12_TAG16_NO_KDF;
    encryptionClient_.setEncryptionAlgorithm(setCryptoAlgorithm);

    final CryptoAlgorithm getCryptoAlgorithm = encryptionClient_.getEncryptionAlgorithm();

    assertEquals(setCryptoAlgorithm, getCryptoAlgorithm);
  }

  @Test(expected = IllegalArgumentException.class)
  public void buildWithoutSpecifiedCommitmentPolicy() throws IOException {
    AwsCrypto.builder().build();
  }

  @Test(expected = IllegalArgumentException.class)
  public void buildWithNullCommitmentPolicy() throws IOException {
    AwsCrypto.builder().withCommitmentPolicy(null).build();
  }

  @Test(expected = AwsCryptoException.class)
  public void setCommittingCryptoAlgorithm() throws IOException {
    final CryptoAlgorithm setCryptoAlgorithm = TestUtils.KEY_COMMIT_CRYPTO_ALG;
    encryptionClient_.setEncryptionAlgorithm(setCryptoAlgorithm);
  }

  @Test(expected = AwsCryptoException.class)
  public void buildWithCommittingCryptoAlgorithm() throws IOException {
    final CryptoAlgorithm setCryptoAlgorithm = TestUtils.KEY_COMMIT_CRYPTO_ALG;
    AwsCrypto.builder()
        .withCommitmentPolicy(commitmentPolicy)
        .withEncryptionAlgorithm(setCryptoAlgorithm)
        .build();
  }

  @Test(expected = AwsCryptoException.class)
  @SuppressWarnings("deprecation")
  public void legacyConstructAndSetCommittingCryptoAlgorithm() throws IOException {
    final CryptoAlgorithm setCryptoAlgorithm = TestUtils.KEY_COMMIT_CRYPTO_ALG;
    AwsCrypto client = new AwsCrypto();
    client.setEncryptionAlgorithm(setCryptoAlgorithm);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setNegativeMaxEdks() {
    AwsCrypto.builder().withMaxEncryptedDataKeys(-1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setZeroMaxEdks() {
    AwsCrypto.builder().withMaxEncryptedDataKeys(0);
  }

  @Test
  public void setValidMaxEdks() {
    for (final int i :
        new int[] {
          1, 10, MESSAGE_FORMAT_MAX_EDKS, MESSAGE_FORMAT_MAX_EDKS + 1, Integer.MAX_VALUE
        }) {
      AwsCrypto.builder().withMaxEncryptedDataKeys(i);
    }
  }

  private MasterKeyProvider<?> providerWithEdks(int numEdks) {
    List<MasterKeyProvider<?>> providers = new ArrayList<>();
    for (int i = 0; i < numEdks; i++) {
      providers.add(masterKeyProvider);
    }
    return MultipleProviderFactory.buildMultiProvider(providers);
  }

  @Test
  public void encryptDecryptWithLessThanMaxEdks() {
    MasterKeyProvider<?> provider = providerWithEdks(2);
    CryptoResult<byte[], ?> result = maxEdksClient_.encryptData(provider, new byte[] {1});
    ParsedCiphertext ciphertext = new ParsedCiphertext(result.getResult());
    assertEquals(ciphertext.getEncryptedKeyBlobCount(), 2);
    maxEdksClient_.decryptData(provider, ciphertext);
  }

  @Test
  public void encryptDecryptWithMaxEdks() {
    MasterKeyProvider<?> provider = providerWithEdks(3);
    CryptoResult<byte[], ?> result = maxEdksClient_.encryptData(provider, new byte[] {1});
    ParsedCiphertext ciphertext = new ParsedCiphertext(result.getResult());
    assertEquals(ciphertext.getEncryptedKeyBlobCount(), 3);
    maxEdksClient_.decryptData(provider, ciphertext);
  }

  @Test
  public void noEncryptWithMoreThanMaxEdks() {
    MasterKeyProvider<?> provider = providerWithEdks(4);
    assertThrows(
        AwsCryptoException.class,
        "Encrypted data keys exceed maxEncryptedDataKeys",
        () -> maxEdksClient_.encryptData(provider, new byte[] {1}));
  }

  @Test
  public void noDecryptWithMoreThanMaxEdks() {
    MasterKeyProvider<?> provider = providerWithEdks(4);
    CryptoResult<byte[], ?> result = noMaxEdksClient_.encryptData(provider, new byte[] {1});
    ParsedCiphertext ciphertext = new ParsedCiphertext(result.getResult());
    assertThrows(
        AwsCryptoException.class,
        "Ciphertext encrypted data keys exceed maxEncryptedDataKeys",
        () -> maxEdksClient_.decryptData(provider, ciphertext));
  }

  @Test
  public void encryptDecryptWithNoMaxEdks() {
    MasterKeyProvider<?> provider = providerWithEdks(MESSAGE_FORMAT_MAX_EDKS);
    CryptoResult<byte[], ?> result = noMaxEdksClient_.encryptData(provider, new byte[] {1});
    ParsedCiphertext ciphertext = new ParsedCiphertext(result.getResult());
    assertEquals(ciphertext.getEncryptedKeyBlobCount(), MESSAGE_FORMAT_MAX_EDKS);
    noMaxEdksClient_.decryptData(provider, ciphertext);
  }

  @Test
  public void encryptDecryptStreamWithLessThanMaxEdks() throws IOException {
    MasterKeyProvider<?> provider = providerWithEdks(2);
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    CryptoOutputStream<?> encryptStream =
        maxEdksClient_.createEncryptingStream(provider, byteArrayOutputStream);
    IOUtils.copy(new ByteArrayInputStream(new byte[] {1}), encryptStream);
    encryptStream.close();

    byte[] ciphertext = byteArrayOutputStream.toByteArray();
    assertEquals(new ParsedCiphertext(ciphertext).getEncryptedKeyBlobCount(), 2);

    byteArrayOutputStream.reset();
    CryptoOutputStream<?> decryptStream =
        maxEdksClient_.createDecryptingStream(provider, byteArrayOutputStream);
    IOUtils.copy(new ByteArrayInputStream(ciphertext), decryptStream);
    decryptStream.close();
  }

  @Test
  public void encryptDecryptStreamWithMaxEdks() throws IOException {
    MasterKeyProvider<?> provider = providerWithEdks(3);
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    CryptoOutputStream<?> encryptStream =
        maxEdksClient_.createEncryptingStream(provider, byteArrayOutputStream);
    IOUtils.copy(new ByteArrayInputStream(new byte[] {1}), encryptStream);
    encryptStream.close();

    byte[] ciphertext = byteArrayOutputStream.toByteArray();
    assertEquals(new ParsedCiphertext(ciphertext).getEncryptedKeyBlobCount(), 3);

    byteArrayOutputStream.reset();
    CryptoOutputStream<?> decryptStream =
        maxEdksClient_.createDecryptingStream(provider, byteArrayOutputStream);
    IOUtils.copy(new ByteArrayInputStream(ciphertext), decryptStream);
    decryptStream.close();
  }

  @Test
  public void noEncryptStreamWithMoreThanMaxEdks() {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    CryptoOutputStream<?> encryptStream =
        maxEdksClient_.createEncryptingStream(providerWithEdks(4), byteArrayOutputStream);
    assertThrows(
        AwsCryptoException.class,
        "Encrypted data keys exceed maxEncryptedDataKeys",
        () -> IOUtils.copy(new ByteArrayInputStream(new byte[] {1}), encryptStream));
  }

  @Test
  public void noDecryptStreamWithMoreThanMaxEdks() throws IOException {
    MasterKeyProvider<?> provider = providerWithEdks(4);
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    CryptoOutputStream<?> encryptStream =
        noMaxEdksClient_.createEncryptingStream(provider, byteArrayOutputStream);
    IOUtils.copy(new ByteArrayInputStream(new byte[] {1}), encryptStream);
    encryptStream.close();

    byte[] ciphertext = byteArrayOutputStream.toByteArray();

    byteArrayOutputStream.reset();
    CryptoOutputStream<?> decryptStream =
        maxEdksClient_.createDecryptingStream(provider, byteArrayOutputStream);
    assertThrows(
        AwsCryptoException.class,
        "Ciphertext encrypted data keys exceed maxEncryptedDataKeys",
        () -> IOUtils.copy(new ByteArrayInputStream(ciphertext), decryptStream));
  }

  @Test
  public void encryptDecryptStreamWithNoMaxEdks() throws IOException {
    MasterKeyProvider<?> provider = providerWithEdks(MESSAGE_FORMAT_MAX_EDKS);
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    CryptoOutputStream<?> encryptStream =
        noMaxEdksClient_.createEncryptingStream(provider, byteArrayOutputStream);
    IOUtils.copy(new ByteArrayInputStream(new byte[] {1}), encryptStream);
    encryptStream.close();

    byte[] ciphertext = byteArrayOutputStream.toByteArray();
    assertEquals(
        new ParsedCiphertext(ciphertext).getEncryptedKeyBlobCount(), MESSAGE_FORMAT_MAX_EDKS);

    byteArrayOutputStream.reset();
    CryptoOutputStream<?> decryptStream =
        noMaxEdksClient_.createDecryptingStream(provider, byteArrayOutputStream);
    IOUtils.copy(new ByteArrayInputStream(ciphertext), decryptStream);
    decryptStream.close();
  }
}
