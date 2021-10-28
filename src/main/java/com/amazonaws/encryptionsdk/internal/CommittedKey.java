// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.management.openmbean.InvalidKeyException;

public final class CommittedKey {

  private final SecretKey key_;
  private final byte[] commitment_;

  CommittedKey(SecretKey key, byte[] commitment) {
    key_ = key;
    commitment_ = commitment;
  }

  public SecretKey getKey() {
    return key_;
  }

  public byte[] getCommitment() {
    return commitment_.clone();
  }

  /**
   * The template for creating the label/info for deriving the encryption key from the data key.
   *
   * <p>Note that this value must be cloned and modified prior to use. Cloned to prevent
   * modification of the template and threading issues. Modified to insert the algorithm id into the
   * first two bytes.
   */
  private static byte[] DERIVE_KEY_LABEL_TEMPLATE = "__DERIVEKEY".getBytes(StandardCharsets.UTF_8);

  /**
   * Full label/info for deriving the key commitment value from the data key.
   *
   * <p>Unlike {@link #DERIVE_KEY_LABEL_TEMPLATE} this value does not need to be cloned or modified
   * prior to use.
   */
  private static byte[] COMMITKEY_LABEL = "COMMITKEY".getBytes(StandardCharsets.UTF_8);

  private static final String RAW_DATA_FORMAT = "RAW";
  private static final String HKDF_SHA_512 = "HkdfSHA512";
  private static final String HMAC_SHA_512 = "HmacSHA512";

  /** Generates an encryption key along with associated commitment value. */
  public static CommittedKey generate(CryptoAlgorithm alg, SecretKey dataKey, byte[] nonce)
      throws InvalidKeyException {
    if (!alg.isCommitting()) {
      throw new IllegalArgumentException("Algorithm does not support key commitment.");
    }
    if (nonce.length != alg.getCommitmentNonceLength()) {
      throw new IllegalArgumentException("Invalid nonce size");
    }
    if (dataKey.getFormat() == null || !dataKey.getFormat().equalsIgnoreCase(RAW_DATA_FORMAT)) {
      throw new IllegalArgumentException(
          "Currently only RAW format keys are supported for HKDF algorithms. Actual format was "
              + dataKey.getFormat());
    }
    if (dataKey.getAlgorithm() == null
        || !dataKey.getAlgorithm().equalsIgnoreCase(alg.getDataKeyAlgo())) {
      throw new IllegalArgumentException(
          "DataKey of incorrect algorithm. Expected "
              + alg.getDataKeyAlgo()
              + " but was "
              + dataKey.getAlgorithm());
    }
    final byte[] rawDataKey = dataKey.getEncoded();
    if (rawDataKey.length != alg.getDataKeyLength()) {
      throw new IllegalArgumentException(
          "DataKey of incorrect length. Expected "
              + alg.getDataKeyLength()
              + " but was "
              + rawDataKey.length);
    }

    final String macAlgorithm;
    switch (alg.getKeyCommitmentAlgo_()) {
      case HKDF_SHA_512:
        macAlgorithm = HMAC_SHA_512;
        break;
      default:
        throw new UnsupportedOperationException(
            "Support for commitment with " + alg.getKeyCommitmentAlgo_() + " not yet built.");
    }

    HmacKeyDerivationFunction kdf = null;
    try {
      kdf = HmacKeyDerivationFunction.getInstance(macAlgorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    kdf.init(rawDataKey, nonce);

    final byte[] commitment = kdf.deriveKey(COMMITKEY_LABEL, alg.getCommitmentLength());

    // Clone to prevent modification of the master copy
    final byte[] deriveKeyLabel = DERIVE_KEY_LABEL_TEMPLATE.clone();
    final short algId = alg.getValue();
    deriveKeyLabel[0] = (byte) ((algId >> 8) & 0xFF);
    deriveKeyLabel[1] = (byte) (algId & 0xFF);
    SecretKey ek =
        new SecretKeySpec(kdf.deriveKey(deriveKeyLabel, alg.getKeyLength()), alg.getKeyAlgo());

    return new CommittedKey(ek, commitment);
  }
}
