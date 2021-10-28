// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static java.util.Collections.emptyList;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DefaultCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class EncryptionHandlerTest {
  private final CryptoAlgorithm cryptoAlgorithm_ =
      CryptoAlgorithm.ALG_AES_192_GCM_IV12_TAG16_NO_KDF;
  private final int frameSize_ = AwsCrypto.getDefaultFrameSize();
  private final Map<String, String> encryptionContext_ = Collections.<String, String>emptyMap();
  private StaticMasterKey masterKeyProvider = new StaticMasterKey("mock");
  private final List<StaticMasterKey> cmks_ = Collections.singletonList(masterKeyProvider);
  private final CommitmentPolicy commitmentPolicy = TestUtils.DEFAULT_TEST_COMMITMENT_POLICY;
  private EncryptionMaterialsRequest testRequest =
      EncryptionMaterialsRequest.newBuilder()
          .setContext(encryptionContext_)
          .setRequestedAlgorithm(cryptoAlgorithm_)
          .build();

  private EncryptionMaterials testResult =
      new DefaultCryptoMaterialsManager(masterKeyProvider).getMaterialsForEncrypt(testRequest);

  @Test
  public void badArguments() {
    assertThrows(
        () -> new EncryptionHandler(frameSize_, testResult.toBuilder().setAlgorithm(null).build()));

    assertThrows(
        () ->
            new EncryptionHandler(
                frameSize_, testResult.toBuilder().setEncryptionContext(null).build()));

    assertThrows(
        () ->
            new EncryptionHandler(
                frameSize_, testResult.toBuilder().setEncryptedDataKeys(null).build()));

    assertThrows(
        () ->
            new EncryptionHandler(
                frameSize_, testResult.toBuilder().setEncryptedDataKeys(emptyList()).build()));

    assertThrows(
        () ->
            new EncryptionHandler(
                frameSize_, testResult.toBuilder().setCleartextDataKey(null).build()));

    assertThrows(
        () ->
            new EncryptionHandler(frameSize_, testResult.toBuilder().setMasterKeys(null).build()));

    assertThrows(() -> new EncryptionHandler(-1, testResult));
  }

  @Test(expected = AwsCryptoException.class)
  public void invalidLenProcessBytes() {
    final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, testResult);

    final byte[] in = new byte[1];
    final byte[] out = new byte[1];
    encryptionHandler.processBytes(in, 0, -1, out, 0);
  }

  @Test(expected = AwsCryptoException.class)
  public void invalidOffsetProcessBytes() {
    final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, testResult);

    final byte[] in = new byte[1];
    final byte[] out = new byte[1];
    encryptionHandler.processBytes(in, -1, in.length, out, 0);
  }

  @Test
  public void whenEncrypting_headerIVIsZero() throws Exception {
    final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, testResult);

    assertArrayEquals(
        new byte[encryptionHandler.getHeaders().getCryptoAlgoId().getNonceLen()],
        encryptionHandler.getHeaders().getHeaderNonce());
  }

  @Test(expected = AwsCryptoException.class)
  public void whenEncryptingV2Algorithm_fails() throws Exception {
    final EncryptionMaterials resultWithV2Alg =
        testResult.toBuilder().setAlgorithm(TestUtils.KEY_COMMIT_CRYPTO_ALG).build();
    final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, resultWithV2Alg);
  }

  @Test
  public void setMaxInputLength() {
    byte[] plaintext = "Don't warn the tadpoles".getBytes();
    final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, testResult);
    encryptionHandler.setMaxInputLength(plaintext.length - 1);

    assertEquals(encryptionHandler.getMaxInputLength(), (long) plaintext.length - 1);

    final byte[] out = new byte[1];
    assertThrows(
        IllegalStateException.class,
        "Plaintext size exceeds max input size limit",
        () -> encryptionHandler.processBytes(plaintext, 0, plaintext.length, out, 0));
  }

  @Test
  public void setMaxInputLengthThrowsIfAlreadyOver() {
    byte[] plaintext = "Don't warn the tadpoles".getBytes();
    final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, testResult);
    final byte[] out = new byte[1024];
    encryptionHandler.processBytes(plaintext, 0, plaintext.length - 1, out, 0);
    assertFalse(encryptionHandler.isComplete());

    assertThrows(
        IllegalStateException.class,
        "Plaintext size exceeds max input size limit",
        () -> encryptionHandler.setMaxInputLength(plaintext.length - 2));
  }

  @Test
  public void setMaxInputLengthAcceptsSmallerValue() {
    final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, testResult);
    encryptionHandler.setMaxInputLength(100);
    assertEquals(encryptionHandler.getMaxInputLength(), 100);

    encryptionHandler.setMaxInputLength(10);
    assertEquals(encryptionHandler.getMaxInputLength(), 10);
  }

  @Test
  public void setMaxInputLengthIgnoresLargerValue() {
    final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, testResult);
    encryptionHandler.setMaxInputLength(10);
    assertEquals(encryptionHandler.getMaxInputLength(), 10);

    encryptionHandler.setMaxInputLength(100);
    assertEquals(encryptionHandler.getMaxInputLength(), 10);
  }
}
