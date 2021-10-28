package com.amazonaws.encryptionsdk.caching;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import org.junit.Test;

public class NullCryptoMaterialsCacheTest {
  @Test
  public void testEncryptPath() {
    NullCryptoMaterialsCache cache = new NullCryptoMaterialsCache();

    EncryptionMaterialsRequest req = CacheTestFixtures.createMaterialsRequest(1);
    EncryptionMaterials result = CacheTestFixtures.createMaterialsResult(req);

    CryptoMaterialsCache.UsageStats stats = new CryptoMaterialsCache.UsageStats(123, 456);
    CryptoMaterialsCache.EncryptCacheEntry entry =
        cache.putEntryForEncrypt(new byte[1], result, () -> Long.MAX_VALUE, stats);
    assertEquals(result, entry.getResult());
    assertFalse(entry.getEntryCreationTime() > System.currentTimeMillis());
    assertEquals(stats, entry.getUsageStats());
    ;

    // the entry should not be in the "cache"
    byte[] cacheId = new byte[1];
    assertNull(cache.getEntryForEncrypt(cacheId, CryptoMaterialsCache.UsageStats.ZERO));

    entry.invalidate(); // shouldn't throw
  }

  @Test
  public void testDecryptPath() {
    NullCryptoMaterialsCache cache = new NullCryptoMaterialsCache();

    DecryptionMaterialsRequest request = CacheTestFixtures.createDecryptRequest(1);
    DecryptionMaterials result = CacheTestFixtures.createDecryptResult(request);

    assertNull(cache.getEntryForDecrypt(new byte[1]));
    cache.putEntryForDecrypt(new byte[1], result, () -> Long.MAX_VALUE);
    assertNull(cache.getEntryForDecrypt(new byte[1]));
  }
}
