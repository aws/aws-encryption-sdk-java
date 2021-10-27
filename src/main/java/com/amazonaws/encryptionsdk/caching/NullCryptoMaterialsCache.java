package com.amazonaws.encryptionsdk.caching;

import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;

/** A {@link CryptoMaterialsCache} that doesn't actually cache anything. */
public class NullCryptoMaterialsCache implements CryptoMaterialsCache {
  @Override
  public EncryptCacheEntry getEntryForEncrypt(byte[] cacheId, final UsageStats usageIncrement) {
    return null;
  }

  @Override
  public EncryptCacheEntry putEntryForEncrypt(
      byte[] cacheId,
      EncryptionMaterials encryptionMaterials,
      CacheHint hint,
      UsageStats initialUsage) {
    return new EncryptCacheEntry() {
      private final long creationTime = System.currentTimeMillis();

      @Override
      public synchronized UsageStats getUsageStats() {
        return initialUsage;
      }

      @Override
      public long getEntryCreationTime() {
        return creationTime;
      }

      @Override
      public EncryptionMaterials getResult() {
        return encryptionMaterials;
      }
    };
  }

  @Override
  public DecryptCacheEntry getEntryForDecrypt(byte[] cacheId) {
    return null;
  }

  @Override
  public void putEntryForDecrypt(
      byte[] cacheId, DecryptionMaterials decryptionMaterials, CacheHint hint) {
    // no-op
  }
}
