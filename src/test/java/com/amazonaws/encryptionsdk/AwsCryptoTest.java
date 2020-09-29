// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static com.amazonaws.encryptionsdk.TestUtils.assertNullChecks;
import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static com.amazonaws.encryptionsdk.TestUtils.isFastTestsOnly;
import static java.util.Collections.singletonMap;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.amazonaws.encryptionsdk.internal.TestKeyring;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import org.junit.Before;
import org.junit.Test;

import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.StaticMasterKey;
import com.amazonaws.encryptionsdk.internal.TestIOUtils;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.CiphertextType;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;

public class AwsCryptoTest {
    private StaticMasterKey masterKeyProvider;
    private Keyring keyring;
    private AwsCrypto forbidCommitmentClient_;
    private AwsCrypto encryptionClient_;
    private static final CommitmentPolicy commitmentPolicy = TestUtils.DEFAULT_TEST_COMMITMENT_POLICY;

    List<CommitmentPolicy> requireWriteCommitmentPolicies = Arrays.asList(
            CommitmentPolicy.RequireEncryptAllowDecrypt, CommitmentPolicy.RequireEncryptRequireDecrypt);

    @Before
    public void init() {
        masterKeyProvider = spy(new StaticMasterKey("testmaterial"));
        keyring = spy(new TestKeyring("testmaterial"));

        forbidCommitmentClient_ = AwsCrypto.builder().withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt).build();
        forbidCommitmentClient_.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256);
        encryptionClient_ = AwsCrypto.standard();
        encryptionClient_.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    private void doEncryptDecrypt(final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

        AwsCrypto client = cryptoAlg.isCommitting() ? encryptionClient_ : forbidCommitmentClient_;
        client.setEncryptionAlgorithm(cryptoAlg);
        client.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = client.encryptData(
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        final byte[] decryptedText = client.decryptData(
                masterKeyProvider,
                cipherText
                ).getResult();

        assertArrayEquals("Bad encrypt/decrypt for " + cryptoAlg, plaintextBytes, decryptedText);
    }

    private void doEncryptDecryptWithKeyring(final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<>(1);
        encryptionContext.put("ENC1", "Encrypt-decrypt-keyring test with %d" + byteSize);

        AwsCrypto client = cryptoAlg.isCommitting() ? encryptionClient_ : forbidCommitmentClient_;
        client.setEncryptionAlgorithm(cryptoAlg);
        client.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = client.encrypt(request -> request
                .keyring(keyring)
                .encryptionContext(encryptionContext)
                .plaintext(plaintextBytes)).getResult();
        final byte[] decryptedText = client.decrypt(request -> request
                .keyring(keyring)
                .ciphertext(cipherText)).getResult();

        assertArrayEquals("Bad encrypt/decrypt for " + cryptoAlg, plaintextBytes, decryptedText);
    }

    private void doTamperedEncryptDecrypt(final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

        AwsCrypto client = cryptoAlg.isCommitting() ? encryptionClient_ : forbidCommitmentClient_;
        client.setEncryptionAlgorithm(cryptoAlg);
        client.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = client.encryptData(
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        cipherText[cipherText.length - 2] ^= (byte) 0xff;

        assertThrows(BadCiphertextException.class, () -> client.decryptData(
            masterKeyProvider,
            cipherText));
    }

    private void doTamperedEncryptDecryptWithKeyring(final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<>(1);
        encryptionContext.put("ENC1", "Encrypt-decrypt-keyring test with %d" + byteSize);

        AwsCrypto client = cryptoAlg.isCommitting() ? encryptionClient_ : forbidCommitmentClient_;
        client.setEncryptionAlgorithm(cryptoAlg);
        client.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = client.encrypt(EncryptRequest.builder()
                .keyring(keyring)
                .plaintext(plaintextBytes).build()).getResult();
        cipherText[cipherText.length - 2] ^= (byte) 0xff;

        assertThrows(BadCiphertextException.class, () -> client.decrypt(DecryptRequest.builder()
                .keyring(keyring)
                .ciphertext(cipherText).build()));

        assertThrows(BadCiphertextException.class, () -> client.decryptData(
            masterKeyProvider,
            cipherText));
    }

    private void doTruncatedEncryptDecrypt(final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<>(1);
        encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

        AwsCrypto client = cryptoAlg.isCommitting() ? encryptionClient_ : forbidCommitmentClient_;
        client.setEncryptionAlgorithm(cryptoAlg);
        client.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = client.encryptData(
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        final byte[] truncatedCipherText = Arrays.copyOf(cipherText, cipherText.length - 1);
        assertThrows(BadCiphertextException.class, () -> client.decryptData(
            masterKeyProvider,
            truncatedCipherText));
    }

    private void doEncryptDecryptWithParsedCiphertext(final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

        AwsCrypto client = cryptoAlg.isCommitting() ? encryptionClient_ : forbidCommitmentClient_;
        client.setEncryptionAlgorithm(cryptoAlg);
        client.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = client.encryptData(
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        ParsedCiphertext pCt = new ParsedCiphertext(cipherText);
        assertEquals(client.getEncryptionAlgorithm(), pCt.getCryptoAlgoId());
        assertEquals(CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA, pCt.getType());
        assertEquals(1, pCt.getEncryptedKeyBlobCount());
        assertEquals(pCt.getEncryptedKeyBlobCount(), pCt.getEncryptedKeyBlobs().size());
        assertEquals(masterKeyProvider.getProviderId(), pCt.getEncryptedKeyBlobs().get(0).getProviderId());
        for (Map.Entry<String, String> e : encryptionContext.entrySet()) {
            assertEquals(e.getValue(), pCt.getEncryptionContextMap().get(e.getKey()));
        }

        final byte[] decryptedText = client.decryptData(
                masterKeyProvider,
                pCt
                ).getResult();

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
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];

                    if (byteSize > 500_000 && isFastTestsOnly()) {
                        continue;
                    }

                    if (byteSize >= 0) {
                        doEncryptDecrypt(cryptoAlg, byteSize, frameSize);
                        doEncryptDecryptWithKeyring(cryptoAlg, byteSize, frameSize);
                    }
                }
            }
        }
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
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];

                    if (byteSize > 500_000 && isFastTestsOnly()) {
                        continue;
                    }

                    if (byteSize >= 0) {
                        doTamperedEncryptDecrypt(cryptoAlg, byteSize, frameSize);
                        doTamperedEncryptDecryptWithKeyring(cryptoAlg, byteSize, frameSize);
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
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

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
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];

                    if (byteSize > 500_000 && isFastTestsOnly()) {
                        continue;
                    }

                    if (byteSize >= 0) {
                        doEncryptDecryptWithParsedCiphertext(cryptoAlg, byteSize, frameSize);
                    }
                }
            }
        }
    }

    @Test
    public void encryptDecryptWithCustomManager() throws Exception {
        boolean[] didDecrypt = new boolean[] { false };

        CryptoMaterialsManager manager = new CryptoMaterialsManager() {
            @Override public EncryptionMaterials getMaterialsForEncrypt(
                    EncryptionMaterialsRequest request
            ) {
                request = request.toBuilder().setContext(singletonMap("foo", "bar")).build();

                EncryptionMaterials encryptionMaterials = new DefaultCryptoMaterialsManager(masterKeyProvider)
                        .getMaterialsForEncrypt(request);

                return encryptionMaterials;
            }

            @Override public DecryptionMaterials decryptMaterials(
                    DecryptionMaterialsRequest request
            ) {
                didDecrypt[0] = true;
                return new DefaultCryptoMaterialsManager(masterKeyProvider).decryptMaterials(request);
            }
        };

        byte[] plaintext = new byte[100];
        CryptoResult<byte[], ?> ciphertext = encryptionClient_.encryptData(manager, plaintext);
        assertEquals("bar", ciphertext.getEncryptionContext().get("foo"));

        // TODO decrypt
        assertFalse(didDecrypt[0]);
        CryptoResult<byte[], ?> plaintextResult = encryptionClient_.decryptData(manager, ciphertext.getResult());
        assertArrayEquals(plaintext, plaintextResult.getResult());
        assertTrue(didDecrypt[0]);
    }

    @Test
    public void encryptDecryptWithCustomManagerWithKeyring() {
        boolean[] didDecrypt = new boolean[] { false };

        CryptoMaterialsManager manager = new CryptoMaterialsManager() {
            @Override public EncryptionMaterials getMaterialsForEncrypt(
                    EncryptionMaterialsRequest request
            ) {
                request = request.toBuilder().setContext(singletonMap("foo", "bar")).build();

                return new DefaultCryptoMaterialsManager(keyring).getMaterialsForEncrypt(request);
            }

            @Override public DecryptionMaterials decryptMaterials(
                    DecryptionMaterialsRequest request
            ) {
                didDecrypt[0] = true;
                return new DefaultCryptoMaterialsManager(keyring).decryptMaterials(request);
            }
        };

        byte[] plaintext = new byte[100];

        AwsCryptoResult<byte[]> ciphertext = encryptionClient_.encrypt(EncryptRequest.builder()
                .cryptoMaterialsManager(manager)
                .plaintext(plaintext).build());
        assertEquals("bar", ciphertext.getEncryptionContext().get("foo"));

        assertFalse(didDecrypt[0]);
        AwsCryptoResult<byte[]>  plaintextResult = encryptionClient_.decrypt(DecryptRequest.builder()
                .cryptoMaterialsManager(manager)
                .ciphertext(ciphertext.getResult()).build());
        assertArrayEquals(plaintext, plaintextResult.getResult());
        assertTrue(didDecrypt[0]);
    }

    @Test
    public void whenCustomCMMIgnoresAlgorithm_throws() throws Exception {
        boolean[] didDecrypt = new boolean[] { false };

        CryptoMaterialsManager manager = new CryptoMaterialsManager() {
            @Override public EncryptionMaterials getMaterialsForEncrypt(
                    EncryptionMaterialsRequest request
            ) {
                request = request.toBuilder().setRequestedAlgorithm(null).build();

                EncryptionMaterials encryptionMaterials = new DefaultCryptoMaterialsManager(masterKeyProvider)
                        .getMaterialsForEncrypt(request);

                return encryptionMaterials;
            }

            @Override public DecryptionMaterials decryptMaterials(
                    DecryptionMaterialsRequest request
            ) {
                didDecrypt[0] = true;
                return new DefaultCryptoMaterialsManager(masterKeyProvider).decryptMaterials(request);
            }
        };

        encryptionClient_.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);

        byte[] plaintext = new byte[100];
        assertThrows(AwsCryptoException.class,
                     () -> encryptionClient_.encryptData(manager, plaintext));
        assertThrows(AwsCryptoException.class,
                     () -> encryptionClient_.estimateCiphertextSize(manager, 12345));
        assertThrows(AwsCryptoException.class,
                     () -> encryptionClient_.createEncryptingStream(manager, new ByteArrayOutputStream()).write(0));
        assertThrows(AwsCryptoException.class,
                     () -> encryptionClient_.createEncryptingStream(manager, new ByteArrayInputStream(new byte[1024*1024])).read());
    }

    @Test
    public void whenCustomCMMUsesCommittingAlgorithmWithForbidPolicy_throws() throws Exception {
        CryptoMaterialsManager manager = new CryptoMaterialsManager() {
            @Override public EncryptionMaterials getMaterialsForEncrypt(
                    EncryptionMaterialsRequest request
            ) {
                EncryptionMaterials encryptionMaterials = new DefaultCryptoMaterialsManager(masterKeyProvider)
                        .getMaterialsForEncrypt(request);

                return encryptionMaterials.toBuilder()
                        .setAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384)
                        .build();
            }

            @Override public DecryptionMaterials decryptMaterials(
                    DecryptionMaterialsRequest request
            ) {
                return new DefaultCryptoMaterialsManager(masterKeyProvider).decryptMaterials(request);
            }
        };

        // create client with null encryption algorithm and ForbidEncrypt policy
        final AwsCrypto client = AwsCrypto.builder().withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt).build();

        byte[] plaintext = new byte[100];
        assertThrows(AwsCryptoException.class,
                () -> client.encryptData(manager, plaintext));
        assertThrows(AwsCryptoException.class,
                () -> client.estimateCiphertextSize(manager, 12345));
        assertThrows(AwsCryptoException.class,
                () -> client.createEncryptingStream(manager, new ByteArrayOutputStream()).write(0));
        assertThrows(AwsCryptoException.class,
                () -> client.createEncryptingStream(manager, new ByteArrayInputStream(new byte[1024*1024])).read());
    }

    @Test
    public void whenDecrypting_invokesMKPOnce() throws Exception {
        byte[] data = encryptionClient_.encryptData(masterKeyProvider, new byte[1]).getResult();

        reset(masterKeyProvider);

        encryptionClient_.decryptData(masterKeyProvider, data);

        verify(masterKeyProvider, times(1)).decryptDataKey(any(), any(), any());
    }

    @Test
    public void whenDecrypting_invokesOnDecryptOnce() throws Exception {
        byte[] data = encryptionClient_.encrypt(EncryptRequest.builder()
                .keyring(keyring)
                .plaintext(new byte[1]).build()).getResult();

        reset(keyring);

        encryptionClient_.decrypt(DecryptRequest.builder()
                .keyring(keyring)
                .ciphertext(data).build());

        verify(keyring, times(1)).onDecrypt(any(), any());
    }

    private void doEstimateCiphertextSize(final CryptoAlgorithm cryptoAlg, final int inLen, final int frameSize) {
        final byte[] plaintext = TestIOUtils.generateRandomPlaintext(inLen);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Ciphertext size estimation test with " + inLen);

        AwsCrypto client = cryptoAlg.isCommitting() ? encryptionClient_ : forbidCommitmentClient_;
        client.setEncryptionAlgorithm(cryptoAlg);
        client.setEncryptionFrameSize(frameSize);

        final long estimatedCiphertextSize = client.estimateCiphertextSize(
                masterKeyProvider,
                inLen,
                encryptionContext);
        final byte[] cipherText = client.encryptData(masterKeyProvider, plaintext,
                encryptionContext).getResult();

        // The estimate should be close (within 16 bytes) and never less than reality
        final String errMsg = "Bad estimation for " + cryptoAlg + " expected: <" + estimatedCiphertextSize
                + "> but was: <" + cipherText.length + ">";
        assertTrue(errMsg, estimatedCiphertextSize - cipherText.length >= 0);
        assertTrue(errMsg, estimatedCiphertextSize - cipherText.length <= 16);
    }

    private void doEstimateCiphertextSizeWithKeyring(final CryptoAlgorithm cryptoAlg, final int inLen, final int frameSize) {
        final byte[] plaintext = TestIOUtils.generateRandomPlaintext(inLen);

        final Map<String, String> encryptionContext = new HashMap<>(1);
        encryptionContext.put("ENC1", "Ciphertext size estimation test with " + inLen);

        AwsCrypto client = cryptoAlg.isCommitting() ? encryptionClient_ : forbidCommitmentClient_;
        client.setEncryptionAlgorithm(cryptoAlg);
        client.setEncryptionFrameSize(frameSize);

        final long estimatedCiphertextSize = client.estimateCiphertextSize(EstimateCiphertextSizeRequest.builder()
                        .keyring(keyring)
                        .encryptionContext(encryptionContext)
                        .plaintextSize(inLen)
                        .build());
        final byte[] cipherText = client.encrypt(EncryptRequest.builder()
                .keyring(keyring)
                .encryptionContext(encryptionContext)
                .plaintext(plaintext).build()).getResult();

        // The estimate should be close (within 16 bytes) and never less than reality
        final String errMsg = "Bad estimation for " + cryptoAlg + " expected: <" + estimatedCiphertextSize
                + "> but was: <" + cipherText.length + ">";
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
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];

                    if (byteSize > 500_000 && isFastTestsOnly()) {
                        continue;
                    }

                    if (byteSize >= 0) {
                        doEstimateCiphertextSize(cryptoAlg, byteSize, frameSize);
                        doEstimateCiphertextSizeWithKeyring(cryptoAlg, byteSize, frameSize);
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

        final long estimatedCiphertextSize = encryptionClient_.estimateCiphertextSize(masterKeyProvider, inLen);
        final byte[] cipherText = encryptionClient_.encryptData(masterKeyProvider, plaintext).getResult();

        final String errMsg = "Bad estimation expected: <" + estimatedCiphertextSize
                + "> but was: <" + cipherText.length + ">";
        assertTrue(errMsg, estimatedCiphertextSize - cipherText.length >= 0);
        assertTrue(errMsg, estimatedCiphertextSize - cipherText.length <= 16);
    }

    @Test
    public void estimateCiphertextSize_usesCachedKeys() throws Exception {
        // Make sure estimateCiphertextSize works with cached CMMs
        CryptoMaterialsManager cmm = spy(new DefaultCryptoMaterialsManager(masterKeyProvider));

        CachingCryptoMaterialsManager cache = CachingCryptoMaterialsManager.newBuilder()
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

        final byte[] cipherText = encryptionClient_.encryptData(masterKeyProvider, plaintextBytes).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                masterKeyProvider,
                cipherText).getResult();

        assertArrayEquals(plaintextBytes, decryptedText);
    }

    @Test
    public void encryptDecryptString() {
        final int ptSize = 1000000; // 1MB
        final String plaintextString = TestIOUtils.generateRandomString(ptSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Test Encryption Context");

        final String ciphertext = encryptionClient_.encryptString(
                masterKeyProvider,
                plaintextString,
                encryptionContext).getResult();
        final String decryptedText = encryptionClient_.decryptString(
                masterKeyProvider,
                ciphertext).getResult();

        assertEquals(plaintextString, decryptedText);
    }

    @Test
    public void encryptDecryptStringWithoutEncContext() {
        final int ptSize = 1000000; // 1MB
        final String plaintextString = TestIOUtils.generateRandomString(ptSize);

        final String cipherText = encryptionClient_.encryptString(masterKeyProvider, plaintextString).getResult();
        final String decryptedText = encryptionClient_.decryptString(
                masterKeyProvider,
                cipherText).getResult();

        assertEquals(plaintextString, decryptedText);
    }

    @Test
    public void encryptBytesDecryptString() {
        final int ptSize = 1000000; // 1MB
        final String plaintext = TestIOUtils.generateRandomString(ptSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Test Encryption Context");

        final byte[] cipherText = encryptionClient_.encryptData(
                masterKeyProvider,
                plaintext.getBytes(StandardCharsets.UTF_8),
                encryptionContext).getResult();
        final String decryptedText = encryptionClient_.decryptString(
                masterKeyProvider,
                Utils.encodeBase64String(cipherText)).getResult();

        assertEquals(plaintext, decryptedText);
    }

    @Test
    public void encryptStringDecryptBytes() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);
        final String plaintextString = new String(plaintextBytes, StandardCharsets.UTF_8);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Test Encryption Context");

        final String ciphertext = encryptionClient_.encryptString(
                masterKeyProvider,
                plaintextString,
                encryptionContext).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                masterKeyProvider,
                Utils.decodeBase64String(ciphertext)).getResult();

        assertArrayEquals(plaintextString.getBytes(StandardCharsets.UTF_8), decryptedText);
    }

    @Test
    public void emptyEncryptionContext() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(0);

        final byte[] cipherText = encryptionClient_.encryptData(
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                masterKeyProvider,
                cipherText).getResult();

        assertArrayEquals(plaintextBytes, decryptedText);
    }

    @Test
    public void decryptMessageWithKeyCommitment() {
        final byte[] cipherText = Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64);
        JceMasterKey masterKey = TestUtils.messageWithCommitKeyMasterKey;
        final CryptoResult decryptedText = encryptionClient_.decryptData(masterKey, cipherText);

        assertEquals(TestUtils.messageWithCommitKeyCryptoAlgorithm, decryptedText.getCryptoAlgorithm());
        assertArrayEquals(Utils.decodeBase64String(TestUtils.messageWithCommitKeyMessageIdBase64), decryptedText.getHeaders().getMessageId());
        assertArrayEquals(Utils.decodeBase64String(TestUtils.messageWithCommitKeyCommitmentBase64), decryptedText.getHeaders().getSuiteData());
        assertArrayEquals(TestUtils.messageWithCommitKeyExpectedResult.getBytes(), (byte[])decryptedText.getResult());
    }

    @Test
    public void decryptMessageWithInvalidKeyCommitment() {
        final byte[] cipherText = Utils.decodeBase64String(TestUtils.invalidMessageWithCommitKeyBase64);
        JceMasterKey masterKey = TestUtils.invalidMessageWithCommitKeyMasterKey;
        assertThrows(BadCiphertextException.class, "Key commitment validation failed. Key identity does not " +
                "match the identity asserted in the message. Halting processing of this message.",
                () -> encryptionClient_.decryptData(masterKey, cipherText));
    }

    // Test that all the parameters that aren't allowed to be null (i.e. all of them) result in immediate NPEs if
    // invoked with null args
    @Test
    public void assertNullValidation() throws Exception {
        byte[] buf = new byte[1];
        HashMap<String, String> context = new HashMap<>();
        MasterKeyProvider provider = masterKeyProvider;
        CryptoMaterialsManager cmm = new DefaultCryptoMaterialsManager(masterKeyProvider);
        InputStream is = new ByteArrayInputStream(new byte[0]);
        OutputStream os = new ByteArrayOutputStream();

        byte[] ciphertext = encryptionClient_.encryptData(cmm, buf).getResult();
        String stringCiphertext = encryptionClient_.encryptString(cmm, "hello, world").getResult();

        assertNullChecks(encryptionClient_, "estimateCiphertextSize",
                                   MasterKeyProvider.class, provider,
                                   Integer.TYPE, 42,
                                   Map.class, context
        );
        assertNullChecks(encryptionClient_, "estimateCiphertextSize",
                                   CryptoMaterialsManager.class, cmm,
                                   Integer.TYPE, 42,
                                   Map.class, context
        );
        assertNullChecks(encryptionClient_, "estimateCiphertextSize",
                                   MasterKeyProvider.class, provider,
                                   Integer.TYPE, 42
        );
        assertNullChecks(encryptionClient_, "estimateCiphertextSize",
                                   CryptoMaterialsManager.class, cmm,
                                   Integer.TYPE, 42
        );
        assertNullChecks(encryptionClient_, "estimateCiphertextSize",
                EstimateCiphertextSizeRequest.class, EstimateCiphertextSizeRequest.builder()
                .cryptoMaterialsManager(cmm)
                .plaintextSize(42).build()
        );
        assertNullChecks(encryptionClient_, "encryptData",
                                   MasterKeyProvider.class, provider,
                                   byte[].class, buf,
                                   Map.class, context
        );
        assertNullChecks(encryptionClient_, "encryptData",
                                   CryptoMaterialsManager.class, cmm,
                                   byte[].class, buf,
                                   Map.class, context
        );
        assertNullChecks(encryptionClient_, "encryptData",
                                   MasterKeyProvider.class, provider,
                                   byte[].class, buf
        );
        assertNullChecks(encryptionClient_, "encryptData",
                                   CryptoMaterialsManager.class, cmm,
                                   byte[].class, buf
        );
        assertNullChecks(encryptionClient_, "encrypt",
                EncryptRequest.class, EncryptRequest.builder()
                .cryptoMaterialsManager(cmm)
                .plaintext(buf).build()
        );
        assertNullChecks(encryptionClient_, "encryptString",
                                   MasterKeyProvider.class, provider,
                                   String.class, "",
                                   Map.class, context
        );
        assertNullChecks(encryptionClient_, "encryptString",
                                   CryptoMaterialsManager.class, cmm,
                                   String.class, "",
                                   Map.class, context
        );
        assertNullChecks(encryptionClient_, "encryptString",
                                   MasterKeyProvider.class, provider,
                                   String.class, ""
        );
        assertNullChecks(encryptionClient_, "encryptString",
                                   CryptoMaterialsManager.class, cmm,
                                   String.class, ""
        );

        assertNullChecks(encryptionClient_, "decryptData",
                                   MasterKeyProvider.class, provider,
                                   byte[].class, ciphertext
        );
        assertNullChecks(encryptionClient_, "decryptData",
                                   CryptoMaterialsManager.class, cmm,
                                   byte[].class, ciphertext
        );
        assertNullChecks(encryptionClient_, "decryptData",
                                   MasterKeyProvider.class, provider,
                                   ParsedCiphertext.class, new ParsedCiphertext(ciphertext)
        );
        assertNullChecks(encryptionClient_, "decryptData",
                                   CryptoMaterialsManager.class, cmm,
                                   ParsedCiphertext.class, new ParsedCiphertext(ciphertext)
        );
        assertNullChecks(encryptionClient_, "decrypt",
                DecryptRequest.class, DecryptRequest.builder()
                .cryptoMaterialsManager(cmm)
                .ciphertext(ciphertext).build()
        );
        assertNullChecks(encryptionClient_, "decryptString",
                                   MasterKeyProvider.class, provider,
                                   String.class, stringCiphertext
        );
        assertNullChecks(encryptionClient_, "decryptString",
                                   CryptoMaterialsManager.class, cmm,
                                   String.class, stringCiphertext
        );

        assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   MasterKeyProvider.class, provider,
                                   OutputStream.class, os,
                                   Map.class, context
                                   );
        assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   OutputStream.class, os,
                                   Map.class, context
        );

        assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   MasterKeyProvider.class, provider,
                                   OutputStream.class, os
        );
        assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   OutputStream.class, os
        );
        assertNullChecks(encryptionClient_, "createEncryptingOutputStream",
                CreateEncryptingOutputStreamRequest.class, CreateEncryptingOutputStreamRequest.builder()
                .cryptoMaterialsManager(cmm)
                .outputStream(os).build()
        );
        assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   MasterKeyProvider.class, provider,
                                   InputStream.class, is,
                                   Map.class, context
        );
        assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   InputStream.class, is,
                                   Map.class, context
        );

        assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   MasterKeyProvider.class, provider,
                                   InputStream.class, is
        );
        assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   InputStream.class, is
        );
        assertNullChecks(encryptionClient_, "createEncryptingInputStream",
                CreateEncryptingInputStreamRequest.class, CreateEncryptingInputStreamRequest.builder()
                        .cryptoMaterialsManager(cmm)
                        .inputStream(is).build()
        );

        assertNullChecks(encryptionClient_, "createDecryptingStream",
                                   MasterKeyProvider.class, provider,
                                   OutputStream.class, os
        );
        assertNullChecks(encryptionClient_, "createDecryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   OutputStream.class, os
        );

        assertNullChecks(encryptionClient_, "createDecryptingStream",
                                   MasterKeyProvider.class, provider,
                                   InputStream.class, is
        );
        assertNullChecks(encryptionClient_, "createDecryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   InputStream.class, is
        );
        assertNullChecks(encryptionClient_, "createDecryptingInputStream",
                CreateDecryptingInputStreamRequest.class, CreateDecryptingInputStreamRequest.builder()
                .cryptoMaterialsManager(cmm)
                .inputStream(is).build()
        );
        assertNullChecks(encryptionClient_, "createDecryptingOutputStream",
                CreateDecryptingOutputStreamRequest.class, CreateDecryptingOutputStreamRequest.builder()
                        .cryptoMaterialsManager(cmm)
                        .outputStream(os).build()
        );
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
        final CryptoAlgorithm setCryptoAlgorithm = CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
        encryptionClient_.setEncryptionAlgorithm(setCryptoAlgorithm);

        final CryptoAlgorithm getCryptoAlgorithm = encryptionClient_.getEncryptionAlgorithm();

        assertEquals(setCryptoAlgorithm, getCryptoAlgorithm);
    }

    @Test(expected = NullPointerException.class)
    public void buildWithNullCommitmentPolicy() throws IOException {
        AwsCrypto.builder().withCommitmentPolicy(null).build();
    }

    @Test
    public void forbidAndSetCommittingCryptoAlgorithm() throws IOException {
        final CryptoAlgorithm setCryptoAlgorithm = CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;

        assertThrows(AwsCryptoException.class, () ->
                AwsCrypto.builder()
                        .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
                        .build()
                        .setEncryptionAlgorithm(setCryptoAlgorithm));
    }

    @Test
    public void requireAndSetNonCommittingCryptoAlgorithm() throws IOException {
        final CryptoAlgorithm setCryptoAlgorithm = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;

        // Default case
        assertThrows(AwsCryptoException.class, () ->
                AwsCrypto.standard().setEncryptionAlgorithm(setCryptoAlgorithm));

        // Test explicitly for every relevant policy
        for (CommitmentPolicy policy : requireWriteCommitmentPolicies) {
            assertThrows(AwsCryptoException.class, () ->
                    AwsCrypto.builder()
                            .withCommitmentPolicy(policy)
                            .build()
                            .setEncryptionAlgorithm(setCryptoAlgorithm));

        }
    }

    @Test
    public void forbidAndBuildWithCommittingCryptoAlgorithm() throws IOException {
        final CryptoAlgorithm setCryptoAlgorithm = CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;

        assertThrows(AwsCryptoException.class, () ->
                AwsCrypto.builder().withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
                        .withEncryptionAlgorithm(setCryptoAlgorithm)
                        .build());
    }

    @Test
    public void requireAndBuildWithNonCommittingCryptoAlgorithm() throws IOException {
        final CryptoAlgorithm setCryptoAlgorithm = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;

        // Test default case
        assertThrows(AwsCryptoException.class, () ->
                AwsCrypto.builder().withEncryptionAlgorithm(setCryptoAlgorithm).build());

        // Test explicitly for every relevant policy
        for (CommitmentPolicy policy : requireWriteCommitmentPolicies) {
            assertThrows(AwsCryptoException.class, () ->
                    AwsCrypto.builder()
                            .withCommitmentPolicy(policy)
                            .withEncryptionAlgorithm(setCryptoAlgorithm)
                            .build());
        }
    }

    @Test
    public void requireCommitmentOnDecryptFailsNonCommitting() throws IOException {
        // Create non-committing ciphertext
        forbidCommitmentClient_.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384);

        final byte[] cipherText = forbidCommitmentClient_.encryptData(
                masterKeyProvider,
                new byte[1],
                new HashMap<>()).getResult();

        // Test explicit policy set
        assertThrows(AwsCryptoException.class, () ->
                AwsCrypto.builder()
                         .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
                         .build()
                         .decryptData(masterKeyProvider, cipherText));

        // Test default builder behavior
        assertThrows(AwsCryptoException.class, () ->
                AwsCrypto.builder()
                         .build()
                         .decryptData(masterKeyProvider, cipherText));

        // Test input stream
        assertThrows(AwsCryptoException.class, () ->
                AwsCrypto.builder()
                         .build()
                         .createDecryptingStream(masterKeyProvider, new ByteArrayInputStream(cipherText))
                         .read());

        // Test output stream
        assertThrows(AwsCryptoException.class, () ->
                AwsCrypto.builder()
                         .build()
                         .createDecryptingStream(masterKeyProvider, new ByteArrayOutputStream())
                         .write(cipherText));
    }

    @Test
    public void whenCustomCMMUsesNonCommittingAlgorithmWithRequirePolicy_throws() throws Exception {
        CryptoMaterialsManager manager = new CryptoMaterialsManager() {
            @Override public EncryptionMaterials getMaterialsForEncrypt(
                    EncryptionMaterialsRequest request
            ) {
                EncryptionMaterials encryptionMaterials = new DefaultCryptoMaterialsManager(masterKeyProvider)
                        .getMaterialsForEncrypt(request);

                return encryptionMaterials.toBuilder()
                        .setAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
                        .build();
            }

            @Override public DecryptionMaterials decryptMaterials(
                    DecryptionMaterialsRequest request
            ) {
                return new DefaultCryptoMaterialsManager(masterKeyProvider).decryptMaterials(request);
            }
        };


        for (CommitmentPolicy policy : requireWriteCommitmentPolicies) {
            // create client with null encryption algorithm and a policy that requires encryption
            final AwsCrypto client = AwsCrypto.builder().withCommitmentPolicy(policy).build();

            byte[] plaintext = new byte[100];
            assertThrows(AwsCryptoException.class,
                    () -> client.encryptData(manager, plaintext));
            assertThrows(AwsCryptoException.class,
                    () -> client.estimateCiphertextSize(manager, 12345));
            assertThrows(AwsCryptoException.class,
                    () -> client.createEncryptingStream(manager, new ByteArrayOutputStream()).write(0));
            assertThrows(AwsCryptoException.class,
                    () -> client.createEncryptingStream(manager, new ByteArrayInputStream(new byte[1024 * 1024])).read());
        }
    }

    @Test
    public void testDecryptMessageWithInvalidCommitment() {
        for (final CryptoAlgorithm cryptoAlg : CryptoAlgorithm.values()) {
            if (!cryptoAlg.isCommitting()) {
                continue;
            }
            final Map<String, String> encryptionContext = new HashMap<String, String>(1);
            encryptionContext.put("Commitment", "Commitment test for %s" + cryptoAlg);
            encryptionClient_.setEncryptionAlgorithm(cryptoAlg);
            byte[] plaintextBytes = new byte[16]; // Actual content doesn't matter
            final byte[] cipherText = encryptionClient_.encryptData(
                    masterKeyProvider,
                    plaintextBytes,
                    encryptionContext).getResult();

            // Find the commitment value
            ParsedCiphertext parsed = new ParsedCiphertext(cipherText);
            final int headerLength = parsed.getOffset();
            // The commitment value is immediately prior to the header tag for v2 encrypted messages
            final int endOfCommitment = headerLength - parsed.getHeaderTag().length;
            // The commitment is 32 bytes long, but if we just index one back from the endOfCommitment we know
            // that we are within it.
            cipherText[endOfCommitment - 1] ^= 0x01; // Tamper with the commitment value

            // Since commitment is verified prior to the header tag, we don't need to worry about actually
            // creating a colliding tag but can just verify that the exception indicates an incorrect commitment
            // value.
            assertThrows(BadCiphertextException.class, "Key commitment validation failed. Key identity does " +
                    "not match the identity asserted in the message. Halting processing of this message.",
                    () -> encryptionClient_.decryptData(masterKeyProvider, cipherText));
        }
    }
}
