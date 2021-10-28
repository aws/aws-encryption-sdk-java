// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static com.amazonaws.encryptionsdk.TestUtils.insecureRandomBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.TestUtils;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

public class CommittedKeyTest {

  @Test
  public void testGenerate() {
    final CryptoAlgorithm algorithm = TestUtils.messageWithCommitKeyCryptoAlgorithm;
    SecretKeySpec secretKey =
        new SecretKeySpec(
            Utils.decodeBase64String(TestUtils.messageWithCommitKeyDEKBase64),
            algorithm.getDataKeyAlgo());
    CommittedKey committedKey =
        CommittedKey.generate(
            algorithm,
            secretKey,
            Utils.decodeBase64String(TestUtils.messageWithCommitKeyMessageIdBase64));
    assertNotNull(committedKey);
    assertEquals(
        committedKey.getKey().getAlgorithm(),
        TestUtils.messageWithCommitKeyCryptoAlgorithm.getKeyAlgo());
    assertArrayEquals(
        committedKey.getCommitment(),
        Utils.decodeBase64String(TestUtils.messageWithCommitKeyCommitmentBase64));
  }

  @Test
  public void testGenerateBadNonceLen() {
    final CryptoAlgorithm algorithm = TestUtils.messageWithCommitKeyCryptoAlgorithm;
    SecretKeySpec secretKey =
        new SecretKeySpec(
            Utils.decodeBase64String(TestUtils.messageWithCommitKeyDEKBase64),
            algorithm.getDataKeyAlgo());
    assertThrows(
        IllegalArgumentException.class,
        "Invalid nonce size",
        () ->
            CommittedKey.generate(
                algorithm, secretKey, new byte[algorithm.getCommitmentNonceLength() + 1]));
  }

  @Test
  public void testGenerateIncorrectMismatchedKeySpecAlgorithm() {
    final CryptoAlgorithm algorithm = TestUtils.messageWithCommitKeyCryptoAlgorithm;
    SecretKeySpec secretKey =
        new SecretKeySpec(new byte[algorithm.getDataKeyLength()], "incorrectAlgorithm");
    assertThrows(
        IllegalArgumentException.class,
        "DataKey of incorrect algorithm.",
        () ->
            CommittedKey.generate(
                algorithm, secretKey, new byte[algorithm.getCommitmentNonceLength()]));
  }

  @Test
  public void testGenerateIncorrectDataKeyLenForAlgorithm() {
    final CryptoAlgorithm algorithm = TestUtils.messageWithCommitKeyCryptoAlgorithm;
    SecretKeySpec secretKey =
        new SecretKeySpec(new byte[algorithm.getDataKeyLength() + 1], algorithm.getDataKeyAlgo());
    assertThrows(
        IllegalArgumentException.class,
        "DataKey of incorrect length.",
        () ->
            CommittedKey.generate(
                algorithm, secretKey, new byte[algorithm.getCommitmentNonceLength()]));
  }

  @Test
  public void testGenerateNonCommittingAlgorithm() {
    final CryptoAlgorithm algorithm = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    SecretKeySpec secretKey =
        new SecretKeySpec(new byte[algorithm.getDataKeyLength()], algorithm.getDataKeyAlgo());
    assertThrows(
        IllegalArgumentException.class,
        "Algorithm does not support key commitment.",
        () ->
            CommittedKey.generate(
                algorithm, secretKey, new byte[algorithm.getCommitmentNonceLength()]));
  }

  @Test
  public void testGenerateCommittedKeySmokeTest() throws Exception {
    // This test intentionally using different techniques
    // to assemble the labels and constants.

    // Commitment Nonce N1 is equal to the Message Id which is a 32 byte random value.
    // Normally this needs to be cryptographically secure, but we can relax this for improved
    // performance in testing.
    final byte[] n1 = insecureRandomBytes(32);

    // Hash for HKDF is SHA-512
    final HmacKeyDerivationFunction hkdf = HmacKeyDerivationFunction.getInstance("HmacSHA512");

    // K_R (Raw keying material, a.k.a. data key) is 256 bits (32 bytes)
    // Normally this needs to be cryptographically secure, but we can relax this for improved
    // performance in testing.
    final byte[] k_r = insecureRandomBytes(32);
    final SecretKey k_rKey =
        new SecretKeySpec(k_r, "HkdfSHA512"); // We also need K_R in this format for later use

    // Output key size for Encryption Key is 256 bits (32 bytes)
    final int l_e = 32;

    // Output key size for Commitment Value is 256 bits (32 bytes)
    final int l_c = 32;

    // KeyLabel is "DERIVEKEY" as UTF-8 encoded bytes
    final byte[] keyLabel = "DERIVEKEY".getBytes(StandardCharsets.UTF_8);

    // CommitLabel is "COMMITKEY" as UTF-8 encoded bytes
    final byte[] commitLabel = "COMMITKEY".getBytes(StandardCharsets.UTF_8);

    // PRK is HKDF-Extract(salt=N_1, initialKeyingMaterial=K_R)
    hkdf.init(k_r /* IKM */, n1 /* Salt */);

    // Not final because we'll rerun this with the other algorithm
    CryptoAlgorithm alg = CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    // Info for K_E is Algorithm ID || KeyLabel.
    // We intentionally construct this in a different manner from the tested implemention.
    // This technique is harder to get wrong but less performant.
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(baos);
    out.writeShort(alg.getValue());
    out.write(keyLabel);
    out.close();

    // K_E := HKDF-Expand(prk=PRK, info=Algorithm ID || KeyLabel, L=L_E)
    byte[] k_e = hkdf.deriveKey(baos.toByteArray(), l_e);

    // K_C = HKDF-Expand(prk=PRK, info=CommitLabel, L=LC)
    final byte[] k_c = hkdf.deriveKey(commitLabel, l_c);

    // Now that we have the expected values, test reality
    CommittedKey committedKey = CommittedKey.generate(alg, k_rKey, n1);
    assertArrayEquals("K_C for " + alg, k_c, committedKey.getCommitment());
    assertArrayEquals("K_E for " + alg, k_e, committedKey.getKey().getEncoded());

    // Now test it with the second algorithm.
    // Since the commitment value doesn't include the algorithm Id,
    // K_C should remain unchanged and only K_E should vary.
    alg = CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
    baos = new ByteArrayOutputStream();
    out = new DataOutputStream(baos);
    out.writeShort(alg.getValue());
    out.write(keyLabel);
    out.close();
    final byte[] k_e2 = hkdf.deriveKey(baos.toByteArray(), l_e);

    // Now that we have the expected values, test reality
    committedKey = CommittedKey.generate(alg, k_rKey, n1);
    assertArrayEquals("K_C for " + alg, k_c, committedKey.getCommitment());
    assertArrayEquals("K_E for " + alg, k_e2, committedKey.getKey().getEncoded());
    assertFalse("K_E must be different for different algorithms", Arrays.areEqual(k_e, k_e2));
  }
}
