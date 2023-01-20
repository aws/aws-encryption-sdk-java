// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DefaultCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.ParsedCiphertext;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import com.amazonaws.encryptionsdk.model.CiphertextType;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;

public class DecryptionHandlerTest {
  private StaticMasterKey masterKeyProvider_;
  private final CommitmentPolicy commitmentPolicy = TestUtils.DEFAULT_TEST_COMMITMENT_POLICY;
  private final CommitmentPolicy requireReadPolicy = CommitmentPolicy.RequireEncryptRequireDecrypt;
  private final List<CommitmentPolicy> allowReadPolicies =
      Arrays.asList(
          CommitmentPolicy.RequireEncryptAllowDecrypt, CommitmentPolicy.ForbidEncryptAllowDecrypt);
  private final SignaturePolicy signaturePolicy = SignaturePolicy.AllowEncryptAllowDecrypt;

  @Before
  public void init() {
    masterKeyProvider_ = new StaticMasterKey("testmaterial");
  }

  @Test(expected = NullPointerException.class)
  public void nullMasterKey() {
    DecryptionHandler.create(
        (MasterKey) null,
        commitmentPolicy,
        signaturePolicy,
        CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
  }

  @Test
  public void nullCommitment() {
    final byte[] ciphertext =
        getTestHeaders(
            CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            CommitmentPolicy.ForbidEncryptAllowDecrypt);

    assertThrows(
        NullPointerException.class,
        () ->
            DecryptionHandler.create(
                masterKeyProvider_,
                new ParsedCiphertext(ciphertext),
                null,
                signaturePolicy,
                CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
    assertThrows(
        NullPointerException.class,
        () ->
            DecryptionHandler.create(
                masterKeyProvider_,
                null,
                signaturePolicy,
                CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
  }

  @Test
  public void nullSignaturePolicy() {
    final byte[] ciphertext =
        getTestHeaders(
            CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            CommitmentPolicy.ForbidEncryptAllowDecrypt);

    assertThrows(
        NullPointerException.class,
        () ->
            DecryptionHandler.create(
                masterKeyProvider_,
                new ParsedCiphertext(ciphertext),
                commitmentPolicy,
                null,
                CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
    assertThrows(
        NullPointerException.class,
        () ->
            DecryptionHandler.create(
                masterKeyProvider_,
                commitmentPolicy,
                null,
                CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
  }

  @Test(expected = AwsCryptoException.class)
  public void invalidLenProcessBytes() {
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            commitmentPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final byte[] in = new byte[1];
    final byte[] out = new byte[1];
    decryptionHandler.processBytes(in, 0, -1, out, 0);
  }

  @Test(expected = AwsCryptoException.class)
  public void maxLenProcessBytes() {
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            commitmentPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    // Create input of size 3 bytes: 1 byte containing version, 1 byte
    // containing type, and 1 byte containing half of the algoId short
    // primitive. Only 1 byte of the algoId is provided because this
    // forces the decryption handler to buffer that 1 byte while waiting for
    // the other byte. We do this so we can specify an input of max
    // value and the total bytes to parse will become max value + 1.
    final byte[] in = new byte[3];
    final byte[] out = new byte[3];
    in[1] = CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA.getValue();

    decryptionHandler.processBytes(in, 0, in.length, out, 0);
    decryptionHandler.processBytes(in, 0, Integer.MAX_VALUE, out, 0);
  }

  @Test
  public void maxInputLength() {
    final byte[] testMessage =
        getTestMessage(
            TestUtils.DEFAULT_TEST_CRYPTO_ALG, CommitmentPolicy.RequireEncryptRequireDecrypt);
    final byte[] out = new byte[100];
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            commitmentPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    decryptionHandler.setMaxInputLength(testMessage.length - 1);

    assertThrows(
        IllegalStateException.class,
        () -> decryptionHandler.processBytes(testMessage, 0, testMessage.length, out, 0));
  }

  @Test
  public void maxInputLengthIncludingParsedCiphertext() {
    final byte[] testMessage =
        getTestMessage(
            TestUtils.DEFAULT_TEST_CRYPTO_ALG, CommitmentPolicy.RequireEncryptRequireDecrypt);
    final byte[] out = new byte[100];
    ParsedCiphertext parsedHeaders = new ParsedCiphertext(testMessage);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            parsedHeaders,
            commitmentPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    decryptionHandler.setMaxInputLength(testMessage.length - 1);

    assertThrows(
        IllegalStateException.class,
        () ->
            decryptionHandler.processBytes(
                testMessage,
                parsedHeaders.getOffset(),
                testMessage.length - parsedHeaders.getOffset(),
                out,
                0));
  }

  @Test
  public void maxInputLengthIncludingCiphertextHeaders() {
    final byte[] testMessage =
        getTestMessage(
            TestUtils.DEFAULT_TEST_CRYPTO_ALG, CommitmentPolicy.RequireEncryptRequireDecrypt);
    final byte[] out = new byte[100];
    ParsedCiphertext parsedHeaders = new ParsedCiphertext(testMessage);
    CiphertextHeaders headers = new CiphertextHeaders();
    headers.deserialize(
        parsedHeaders.getCiphertext(), 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            headers,
            commitmentPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    decryptionHandler.setMaxInputLength(testMessage.length - 1);

    assertThrows(
        IllegalStateException.class,
        () ->
            decryptionHandler.processBytes(
                testMessage,
                parsedHeaders.getOffset(),
                testMessage.length - parsedHeaders.getOffset(),
                out,
                0));
  }

  @Test(expected = BadCiphertextException.class)
  public void headerIntegrityFailure() {
    byte[] ciphertext = getTestHeaders();

    // tamper the fifth byte in the header which corresponds to the first
    // byte of the message identifier. We do this because tampering the
    // first four bytes will be detected as invalid values during parsing.
    ciphertext[5] += 1;

    // attempt to decrypt with the tampered header.
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            commitmentPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
    final byte[] plaintext = new byte[plaintextLen];
    decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
  }

  @Test(expected = BadCiphertextException.class)
  public void invalidVersion() {
    byte[] ciphertext = getTestHeaders();

    // set byte containing version to invalid value.
    ciphertext[0] = 0; // NOTE: This will need to be updated should 0 ever be a valid version

    // attempt to decrypt with the tampered header.
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            commitmentPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
    final byte[] plaintext = new byte[plaintextLen];
    decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
  }

  @Test(expected = AwsCryptoException.class)
  public void invalidCMK() {
    final byte[] ciphertext = getTestHeaders();

    masterKeyProvider_.setKeyId(masterKeyProvider_.getKeyId() + "nonsense");

    // attempt to decrypt with the tampered header.
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            commitmentPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
    final byte[] plaintext = new byte[plaintextLen];
    decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
  }

  @Test
  public void validAlgForCommitmentPolicyCreate() {
    // ensure we can decrypt non-committing algs with the policies that allow it
    final CryptoAlgorithm nonCommittingAlg = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    for (CommitmentPolicy policy : allowReadPolicies) {
      final byte[] ciphertext =
          getTestHeaders(nonCommittingAlg, CommitmentPolicy.ForbidEncryptAllowDecrypt);
      final DecryptionHandler<StaticMasterKey> decryptionHandler =
          DecryptionHandler.create(
              masterKeyProvider_,
              policy,
              signaturePolicy,
              CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
      // expected plaintext is zero length
      final byte[] plaintext = new byte[0];
      ProcessingSummary processingSummary =
          decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
      assertEquals(ciphertext.length, processingSummary.getBytesProcessed());
      assertArrayEquals(new byte[0], plaintext);
    }

    // ensure we can decrypt committing algs with all policies
    final CryptoAlgorithm committingAlg = CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    for (CommitmentPolicy policy : CommitmentPolicy.values()) {
      final byte[] ciphertext =
          getTestHeaders(committingAlg, CommitmentPolicy.RequireEncryptRequireDecrypt);
      final DecryptionHandler<StaticMasterKey> decryptionHandler =
          DecryptionHandler.create(
              masterKeyProvider_,
              policy,
              signaturePolicy,
              CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
      // expected plaintext is zero length
      final byte[] plaintext = new byte[0];
      ProcessingSummary processingSummary =
          decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
      assertEquals(ciphertext.length, processingSummary.getBytesProcessed());
      assertArrayEquals(new byte[0], plaintext);
    }
  }

  @Test
  public void invalidAlgForCommitmentPolicyCreateWithoutHeaders() {
    final CryptoAlgorithm nonCommittingAlg =
        CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    final byte[] ciphertext =
        getTestHeaders(nonCommittingAlg, CommitmentPolicy.ForbidEncryptAllowDecrypt);

    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            requireReadPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
    final byte[] plaintext = new byte[plaintextLen];

    assertThrows(
        AwsCryptoException.class,
        () -> decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0));
  }

  @Test
  public void invalidAlgForCommitmentPolicyCreateWithHeaders() {
    final CryptoAlgorithm nonCommittingAlg =
        CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    final byte[] ciphertext =
        getTestHeaders(nonCommittingAlg, CommitmentPolicy.ForbidEncryptAllowDecrypt);

    assertThrows(
        AwsCryptoException.class,
        () ->
            DecryptionHandler.create(
                masterKeyProvider_,
                new ParsedCiphertext(ciphertext),
                requireReadPolicy,
                signaturePolicy,
                CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
  }

  @Test
  public void validAlgForSignaturePolicyCreate() {
    // ensure we can decrypt non-signing algs with the policy that allows it
    final CryptoAlgorithm nonSigningAlg = CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    final byte[] ciphertext = getTestHeaders(nonSigningAlg, commitmentPolicy);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            commitmentPolicy,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    // expected plaintext is zero length
    final byte[] plaintext = new byte[0];
    ProcessingSummary processingSummary =
        decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
    assertEquals(ciphertext.length, processingSummary.getBytesProcessed());
    assertArrayEquals(new byte[0], plaintext);
  }

  @Test
  public void invalidAlgForSignaturePolicyCreateWithoutHeaders() {
    final CryptoAlgorithm signingAlg =
        CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
    final byte[] ciphertext = getTestHeaders(signingAlg, commitmentPolicy);

    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            commitmentPolicy,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
    final byte[] plaintext = new byte[plaintextLen];

    assertThrows(
        AwsCryptoException.class,
        () -> decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0));
  }

  @Test
  public void invalidAlgForSignaturePolicyCreateWithHeaders() {
    final CryptoAlgorithm signingAlg =
        CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
    final byte[] ciphertext = getTestHeaders(signingAlg, commitmentPolicy);

    assertThrows(
        AwsCryptoException.class,
        () ->
            DecryptionHandler.create(
                masterKeyProvider_,
                new ParsedCiphertext(ciphertext),
                commitmentPolicy,
                SignaturePolicy.AllowEncryptForbidDecrypt,
                CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS));
  }

  private byte[] getTestHeaders() {
    return getTestHeaders(
        TestUtils.DEFAULT_TEST_CRYPTO_ALG, TestUtils.DEFAULT_TEST_COMMITMENT_POLICY, 1);
  }

  private byte[] getTestHeaders(CryptoAlgorithm cryptoAlgorithm, CommitmentPolicy policy) {
    return getTestHeaders(cryptoAlgorithm, policy, 1);
  }

  private byte[] getTestHeaders(int numEdks) {
    return getTestHeaders(
        TestUtils.DEFAULT_TEST_CRYPTO_ALG, TestUtils.DEFAULT_TEST_COMMITMENT_POLICY, numEdks);
  }

  private byte[] getTestHeaders(
      CryptoAlgorithm cryptoAlgorithm, CommitmentPolicy policy, int numEdks) {
    // Note that it's questionable to assume that failing to call doFinal() on the encryption
    // handler
    // always results in only outputting the header!
    return getTestMessage(cryptoAlgorithm, policy, numEdks, false);
  }

  private byte[] getTestMessage(CryptoAlgorithm cryptoAlgorithm, CommitmentPolicy policy) {
    return getTestMessage(cryptoAlgorithm, policy, 1, true);
  }

  private byte[] getTestMessage(
      CryptoAlgorithm cryptoAlgorithm, CommitmentPolicy policy, int numEdks, boolean doFinal) {
    final int frameSize_ = AwsCrypto.getDefaultFrameSize();
    final Map<String, String> encryptionContext = Collections.<String, String>emptyMap();

    final EncryptionMaterialsRequest encryptionMaterialsRequest =
        EncryptionMaterialsRequest.newBuilder()
            .setContext(encryptionContext)
            .setRequestedAlgorithm(cryptoAlgorithm)
            .setCommitmentPolicy(policy)
            .build();

    List<MasterKeyProvider<?>> providers = new ArrayList<>();
    for (int i = 0; i < numEdks; i++) {
      providers.add(masterKeyProvider_);
    }
    MasterKeyProvider<?> provider = MultipleProviderFactory.buildMultiProvider(providers);

    final EncryptionMaterials encryptionMaterials =
        new DefaultCryptoMaterialsManager(provider)
            .getMaterialsForEncrypt(encryptionMaterialsRequest);

    final EncryptionHandler encryptionHandler =
        new EncryptionHandler(frameSize_, encryptionMaterials, policy);

    // create the ciphertext headers by calling encryption handler.
    final byte[] in = new byte[0];
    final int ciphertextLen = encryptionHandler.estimateOutputSize(in.length);
    final byte[] ciphertext = new byte[ciphertextLen];
    ProcessingSummary summary = encryptionHandler.processBytes(in, 0, in.length, ciphertext, 0);
    if (doFinal) {
      encryptionHandler.doFinal(ciphertext, summary.getBytesWritten());
    }
    return ciphertext;
  }

  @Test(expected = AwsCryptoException.class)
  public void invalidOffsetProcessBytes() {
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            commitmentPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final byte[] in = new byte[1];
    final byte[] out = new byte[1];
    decryptionHandler.processBytes(in, -1, in.length, out, 0);
  }

  @Test(expected = BadCiphertextException.class)
  public void incompleteCiphertext() {
    byte[] ciphertext = getTestHeaders();

    CiphertextHeaders h = new CiphertextHeaders();
    h.deserialize(ciphertext, 0, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);

    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            commitmentPolicy,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final byte[] out = new byte[1];

    // Note the " - 1" is a bit deceptive: the ciphertext SHOULD already be incomplete because we
    // called getTestHeaders() above, so the whole body is missing!
    decryptionHandler.processBytes(ciphertext, 0, ciphertext.length - 1, out, 0);
    decryptionHandler.doFinal(out, 0);
  }

  @Test
  public void incompleteCiphertextV2() {
    byte[] ciphertext = Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64);
    final DecryptionHandler<JceMasterKey> decryptionHandler =
        DecryptionHandler.create(
            TestUtils.messageWithCommitKeyMasterKey,
            CommitmentPolicy.RequireEncryptRequireDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final byte[] out = new byte[1];

    decryptionHandler.processBytes(ciphertext, 0, ciphertext.length - 1, out, 0);
    assertThrows(
        BadCiphertextException.class,
        "Unable to process entire ciphertext.",
        () -> decryptionHandler.doFinal(out, 0));
  }

  @Test
  public void incompleteCiphertextSigned() {
    byte[] ciphertext =
        getTestMessage(
            CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
            CommitmentPolicy.RequireEncryptRequireDecrypt);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            CommitmentPolicy.RequireEncryptRequireDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final byte[] out = new byte[1];

    decryptionHandler.processBytes(ciphertext, 0, ciphertext.length - 1, out, 0);
    assertThrows(
        BadCiphertextException.class,
        "Unable to process entire ciphertext.",
        () -> decryptionHandler.doFinal(out, 0));
  }

  @Test
  public void headerV2HeaderIntegrityFailure() {
    byte[] ciphertext = Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64);

    // Tamper the bytes that corresponds to the frame length.
    // This is the only reasonable way to tamper with this handcrafted message's
    // header which can still be successfully parsed.
    ciphertext[134] += 1;

    // attempt to decrypt with the tampered header.
    final DecryptionHandler<JceMasterKey> decryptionHandler =
        DecryptionHandler.create(
            TestUtils.messageWithCommitKeyMasterKey,
            CommitmentPolicy.RequireEncryptRequireDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
    final byte[] plaintext = new byte[plaintextLen];
    assertThrows(
        BadCiphertextException.class,
        "Header integrity check failed",
        () -> decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0));
  }

  @Test
  public void headerV2BodyIntegrityFailure() {
    byte[] ciphertext = Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64);

    // Tamper the bytes that corresponds to the body auth
    ciphertext[ciphertext.length - 1] += 1;

    // attempt to decrypt with the tampered header.
    final DecryptionHandler<JceMasterKey> decryptionHandler =
        DecryptionHandler.create(
            TestUtils.messageWithCommitKeyMasterKey,
            CommitmentPolicy.RequireEncryptRequireDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
    final byte[] plaintext = new byte[plaintextLen];
    assertThrows(
        BadCiphertextException.class,
        "Tag mismatch",
        () -> decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0));
  }

  @Test
  public void withLessThanMaxEdks() {
    byte[] header = getTestHeaders(2);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_, CommitmentPolicy.RequireEncryptAllowDecrypt, signaturePolicy, 3);
    final int plaintextLen = decryptionHandler.estimateOutputSize(header.length);
    final byte[] plaintext = new byte[plaintextLen];
    decryptionHandler.processBytes(header, 0, header.length, plaintext, 0);
  }

  @Test
  public void withMaxEdks() {
    byte[] header = getTestHeaders(3);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_, CommitmentPolicy.RequireEncryptAllowDecrypt, signaturePolicy, 3);
    final int plaintextLen = decryptionHandler.estimateOutputSize(header.length);
    final byte[] plaintext = new byte[plaintextLen];
    decryptionHandler.processBytes(header, 0, header.length, plaintext, 0);
  }

  @Test
  public void withMoreThanMaxEdks() {
    byte[] header = getTestHeaders(4);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_, CommitmentPolicy.RequireEncryptAllowDecrypt, signaturePolicy, 3);
    final int plaintextLen = decryptionHandler.estimateOutputSize(header.length);
    final byte[] plaintext = new byte[plaintextLen];
    assertThrows(
        AwsCryptoException.class,
        "Ciphertext encrypted data keys exceed maxEncryptedDataKeys",
        () -> decryptionHandler.processBytes(header, 0, header.length, plaintext, 0));
  }

  @Test
  public void withNoMaxEdks() {
    byte[] header = getTestHeaders(1 << 16 - 1);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            CommitmentPolicy.RequireEncryptAllowDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final int plaintextLen = decryptionHandler.estimateOutputSize(header.length);
    final byte[] plaintext = new byte[plaintextLen];
    decryptionHandler.processBytes(header, 0, header.length, plaintext, 0);
  }

  @Test
  public void validSignatureAcrossMultipleBlocks() {
    byte[] ciphertext =
        getTestMessage(
            CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
            CommitmentPolicy.RequireEncryptRequireDecrypt);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            CommitmentPolicy.RequireEncryptRequireDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final byte[] out = new byte[1];

    // Parse the header and body
    final int headerLength = 388;
    decryptionHandler.processBytes(ciphertext, 0, headerLength, out, 0);

    // Parse the footer across two calls
    // This used to fail to verify the signature because partial bytes were dropped instead.
    // The overall decryption would still succeed because the completeness check in doFinal
    // used to not include the footer.
    // The number of bytes read in the first chunk is completely arbitrary. The
    // parameterized CryptoOutputStreamTest tests covers lots of possible chunk
    // sizes much more thoroughly. This is just a very explicit regression unit test for a known
    // issue that is now fixed.
    final int firstChunkLength = 12;
    final int firstChunkOffset = headerLength;
    final int secondChunkOffset = headerLength + firstChunkLength;
    final int secondChunkLength = ciphertext.length - secondChunkOffset;
    decryptionHandler.processBytes(ciphertext, firstChunkOffset, firstChunkLength, out, 0);
    decryptionHandler.processBytes(ciphertext, secondChunkOffset, secondChunkLength, out, 0);
    decryptionHandler.doFinal(out, 0);
  }

  @Test
  public void invalidSignatureAcrossMultipleBlocks() {
    byte[] ciphertext =
        getTestMessage(
            CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
            CommitmentPolicy.RequireEncryptRequireDecrypt);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            CommitmentPolicy.RequireEncryptRequireDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final byte[] out = new byte[1];

    // Parse the header and body
    decryptionHandler.processBytes(ciphertext, 0, 388, out, 0);

    // Process extra bytes before processing the actual signature bytes.
    // This used to actually work because the handler failed to buffer the unparsed bytes
    // across calls. To regression test this properly we have to parse the two bytes for the
    // length...
    decryptionHandler.processBytes(ciphertext, 388, 2, out, 0);
    // ...and after that any bytes fewer than that length would previously be dropped.
    decryptionHandler.processBytes(new byte[10], 0, 10, out, 0);
    assertThrows(
        BadCiphertextException.class,
        "Bad trailing signature",
        () -> decryptionHandler.processBytes(ciphertext, 390, ciphertext.length - 390, out, 0));
  }

  @Test
  public void setMaxInputLength() {
    byte[] ciphertext =
        getTestMessage(
            CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
            CommitmentPolicy.RequireEncryptRequireDecrypt);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            CommitmentPolicy.RequireEncryptRequireDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    decryptionHandler.setMaxInputLength(ciphertext.length - 1);

    assertEquals(decryptionHandler.getMaxInputLength(), (long) ciphertext.length - 1);

    final byte[] out = new byte[1];
    assertThrows(
        IllegalStateException.class,
        "Ciphertext size exceeds size bound",
        () -> decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, out, 0));
  }

  @Test
  public void setMaxInputLengthThrowsIfAlreadyOver() {
    byte[] ciphertext =
        getTestMessage(
            CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
            CommitmentPolicy.RequireEncryptRequireDecrypt);
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            CommitmentPolicy.RequireEncryptRequireDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    final byte[] out = new byte[1];
    decryptionHandler.processBytes(ciphertext, 0, ciphertext.length - 1, out, 0);
    assertFalse(decryptionHandler.isComplete());

    assertThrows(
        IllegalStateException.class,
        "Ciphertext size exceeds size bound",
        () -> decryptionHandler.setMaxInputLength(ciphertext.length - 2));
  }

  @Test
  public void setMaxInputLengthAcceptsSmallerValue() {
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            CommitmentPolicy.RequireEncryptRequireDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    decryptionHandler.setMaxInputLength(100);
    assertEquals(decryptionHandler.getMaxInputLength(), 100);

    decryptionHandler.setMaxInputLength(10);
    assertEquals(decryptionHandler.getMaxInputLength(), 10);
  }

  @Test
  public void setMaxInputLengthIgnoresLargerValue() {
    final DecryptionHandler<StaticMasterKey> decryptionHandler =
        DecryptionHandler.create(
            masterKeyProvider_,
            CommitmentPolicy.RequireEncryptRequireDecrypt,
            signaturePolicy,
            CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    decryptionHandler.setMaxInputLength(10);
    assertEquals(decryptionHandler.getMaxInputLength(), 10);

    decryptionHandler.setMaxInputLength(100);
    assertEquals(decryptionHandler.getMaxInputLength(), 10);
  }
}
