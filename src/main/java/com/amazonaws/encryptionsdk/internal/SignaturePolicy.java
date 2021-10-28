package com.amazonaws.encryptionsdk.internal;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;

public enum SignaturePolicy {
  AllowEncryptAllowDecrypt {
    @Override
    public boolean algorithmAllowedForDecrypt(CryptoAlgorithm algorithm) {
      return true;
    }
  },
  AllowEncryptForbidDecrypt {
    @Override
    public boolean algorithmAllowedForDecrypt(CryptoAlgorithm algorithm) {
      return algorithm.getTrailingSignatureLength() == 0;
    }
  };

  public abstract boolean algorithmAllowedForDecrypt(CryptoAlgorithm algorithm);
}
