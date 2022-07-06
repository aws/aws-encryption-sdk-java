// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

/**
 * Governs how a AwsCrypto behaves during configuration, encryption, and decryption, with respect to
 * key commitment.
 */
public enum CommitmentPolicy {
  /**
   * On encrypty, algorithm suite must NOT support key commitment; On decrypt, if a key commitment
   * is present on the ciphertext, then the key commitment must be valid. Key commitment will NOT be
   * included in ciphertext on encrypt.
   */
  ForbidEncryptAllowDecrypt,
  /**
   * On encrypt, algorithm suite must support key commitment; On decrypt, if a key commitment is
   * present on the ciphertext, then the key commitment must be valid. Key commitment will be
   * included in ciphertext on encrypt.
   */
  RequireEncryptAllowDecrypt,
  /**
   * Algorithm suite must support key commitment. Key commitment will be included in ciphertext on
   * encrypt. Valid key commitment must be present in ciphertext on decrypt.
   */
  RequireEncryptRequireDecrypt;

  /** Validates that an algorithm meets the Policy's On encrypt key commitment. */
  public boolean algorithmAllowedForEncrypt(CryptoAlgorithm algorithm) {
    switch (this) {
      case ForbidEncryptAllowDecrypt:
        return !algorithm.isCommitting();
      case RequireEncryptAllowDecrypt:
      case RequireEncryptRequireDecrypt:
        return algorithm.isCommitting();
      default:
        throw new UnsupportedOperationException(
            "Support for commitment policy " + this + " not yet built.");
    }
  }

  /** Validates that an algorithm meets the Policy's On decrypt key commitment. */
  public boolean algorithmAllowedForDecrypt(CryptoAlgorithm algorithm) {
    switch (this) {
      case ForbidEncryptAllowDecrypt:
      case RequireEncryptAllowDecrypt:
        return true;
      case RequireEncryptRequireDecrypt:
        return algorithm.isCommitting();
      default:
        throw new UnsupportedOperationException(
            "Support for commitment policy " + this + " not yet built.");
    }
  }
}
