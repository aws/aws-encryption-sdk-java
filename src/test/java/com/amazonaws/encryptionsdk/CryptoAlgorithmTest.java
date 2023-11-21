// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.EncryptionHandler;
import com.amazonaws.encryptionsdk.internal.StaticMasterKey;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsHandler;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import java.security.InvalidKeyException;
import java.util.Collections;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

public class CryptoAlgorithmTest {
  @Test
  public void testDeserialization() {
    for (CryptoAlgorithm algorithm : CryptoAlgorithm.values()) {
      assertEquals(
          algorithm.toString(),
          algorithm,
          CryptoAlgorithm.deserialize(algorithm.getMessageFormatVersion(), algorithm.getValue()));
    }
  }

  @Test
  public void testGetCommittedEncryptionKey() throws InvalidKeyException {
    CryptoAlgorithm algorithm = TestUtils.messageWithCommitKeyCryptoAlgorithm;
    SecretKeySpec secretKey =
        new SecretKeySpec(
            Utils.decodeBase64String(TestUtils.messageWithCommitKeyDEKBase64),
            algorithm.getDataKeyAlgo());
    CiphertextHeaders headers =
        new ParsedCiphertext(Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64));
    SecretKey key = algorithm.getEncryptionKeyFromDataKey(secretKey, headers);
    assertNotNull(key);
    assertEquals(algorithm.getKeyAlgo(), key.getAlgorithm());
  }

  @Test
  public void testGetCommittedEncryptionKeyIncorrectCommitment() throws InvalidKeyException {
    CryptoAlgorithm algorithm = TestUtils.messageWithCommitKeyCryptoAlgorithm;
    SecretKeySpec secretKey =
        new SecretKeySpec(
            Utils.decodeBase64String(TestUtils.messageWithCommitKeyDEKBase64),
            algorithm.getDataKeyAlgo());
    CiphertextHeaders headers =
        new ParsedCiphertext(Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64));

    // Set header to an incorrect commitment value
    headers.setSuiteData(new byte[algorithm.getSuiteDataLength()]);
    assertThrows(
        BadCiphertextException.class,
        "Key commitment validation failed. Key identity does not match the "
            + "identity asserted in the message. Halting processing of this message.",
        () -> algorithm.getEncryptionKeyFromDataKey(secretKey, headers));
  }

  @Test
  public void testGetCommittedEncryptionKeyIncorrectKeySpecAlgorithm() throws InvalidKeyException {
    CryptoAlgorithm algorithm = TestUtils.messageWithCommitKeyCryptoAlgorithm;
    SecretKeySpec secretKey =
        new SecretKeySpec(new byte[algorithm.getDataKeyLength()], "incorrectAlgorithm");
    CiphertextHeaders headers =
        new ParsedCiphertext(Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64));
    assertThrows(
        InvalidKeyException.class,
        "DataKey of incorrect algorithm.",
        () -> algorithm.getEncryptionKeyFromDataKey(secretKey, headers));
  }

  @Test
  public void testGetCommittedEncryptionKeyIncorrectLength() throws InvalidKeyException {
    CryptoAlgorithm algorithm = TestUtils.messageWithCommitKeyCryptoAlgorithm;
    SecretKeySpec secretKey = new SecretKeySpec(new byte[1], "HkdfSHA512");
    CiphertextHeaders headers =
        new ParsedCiphertext(Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64));
    assertThrows(
        IllegalArgumentException.class,
        "DataKey of incorrect length.",
        () -> algorithm.getEncryptionKeyFromDataKey(secretKey, headers));
  }

  @Test
  public void testGetUnCommittedEncryptionKey() throws InvalidKeyException {
    CryptoAlgorithm algo = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    SecretKeySpec secretKey =
        new SecretKeySpec(new byte[algo.getDataKeyLength()], algo.getDataKeyAlgo());
    CiphertextHeaders headers = getTestHeaders(algo);
    SecretKey key = algo.getEncryptionKeyFromDataKey(secretKey, headers);
    assertNotNull(key);
    assertEquals(algo.getKeyAlgo(), key.getAlgorithm());
  }

  @Test
  public void testGetUnCommittedEncryptionKeyFromDataKeyIncorrectKeySpecAlgorithm()
      throws InvalidKeyException {
    CryptoAlgorithm algo = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    SecretKeySpec secretKey =
        new SecretKeySpec(new byte[algo.getDataKeyLength()], "incorrectAlgorithm");
    CiphertextHeaders headers = getTestHeaders(algo);
    assertThrows(
        InvalidKeyException.class,
        "DataKey of incorrect algorithm.",
        () ->
            TestUtils.messageWithCommitKeyCryptoAlgorithm.getEncryptionKeyFromDataKey(
                secretKey, headers));
  }

  @Test
  public void testGetUnCommittedEncryptionKeyIncorrectLength() throws InvalidKeyException {
    SecretKeySpec secretKey = new SecretKeySpec(new byte[1], "HkdfSHA512");
    CiphertextHeaders headers =
        new ParsedCiphertext(Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64));
    assertThrows(
        IllegalArgumentException.class,
        "DataKey of incorrect length.",
        () ->
            TestUtils.messageWithCommitKeyCryptoAlgorithm.getEncryptionKeyFromDataKey(
                secretKey, headers));
  }

  private ParsedCiphertext getTestHeaders(CryptoAlgorithm algo) {
    // Generate test headers
    final int frameSize_ = AwsCrypto.getDefaultFrameSize();
    final Map<String, String> encryptionContext = Collections.<String, String>emptyMap();
    final CommitmentPolicy policy = CommitmentPolicy.ForbidEncryptAllowDecrypt;

    final EncryptionMaterialsRequest encryptionMaterialsRequest =
        EncryptionMaterialsRequest.newBuilder()
            .setContext(encryptionContext)
            .setRequestedAlgorithm(algo)
            .setCommitmentPolicy(policy)
            .build();

    final StaticMasterKey masterKeyProvider = new StaticMasterKey("mock");

    final EncryptionMaterials encryptionMaterials =
        new DefaultCryptoMaterialsManager(masterKeyProvider)
            .getMaterialsForEncrypt(encryptionMaterialsRequest);

    final EncryptionHandler encryptionHandler =
        new EncryptionHandler(
            frameSize_, new EncryptionMaterialsHandler(encryptionMaterials), policy);

    final byte[] in = new byte[0];
    final int ciphertextLen = encryptionHandler.estimateOutputSize(in.length);
    final byte[] ciphertext = new byte[ciphertextLen];
    encryptionHandler.processBytes(in, 0, in.length, ciphertext, 0);
    return new ParsedCiphertext(ciphertext);
  }
}
