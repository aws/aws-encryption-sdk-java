package com.amazonaws.encryptionsdk.caching;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import com.amazonaws.encryptionsdk.caching.CryptoMaterialsCache.UsageStats;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Optional;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class LocalCryptoMaterialsCacheTest {
  public static final String PARTTION_NAME = "foo";
  FakeClock clock;
  LocalCryptoMaterialsCache cache;
  CryptoMaterialsCache.CacheHint hint = () -> 1000; // maxAge = 1000

  @Before
  public void setUp() {
    clock = new FakeClock();
    cache = new LocalCryptoMaterialsCache(5);
    cache.clock = clock;
  }

  @Test
  public void whenNoEntriesInCache_noEntriesReturned() {
    assertNull(cache.getEntryForDecrypt(new byte[10]));
    byte[] cacheId = new byte[10];
    assertNull(cache.getEntryForEncrypt(cacheId, UsageStats.ZERO));
  }

  @Test
  public void whenEntriesAddedToDecryptCache_correctEntriesReturned() {
    DecryptionMaterials result1 =
        CacheTestFixtures.createDecryptResult(CacheTestFixtures.createDecryptRequest(1));
    DecryptionMaterials result2 =
        CacheTestFixtures.createDecryptResult(CacheTestFixtures.createDecryptRequest(2));

    cache.putEntryForDecrypt(new byte[] {1}, result1, hint);
    cache.putEntryForDecrypt(new byte[] {2}, result2, hint);
    assertEquals(result2, cache.getEntryForDecrypt(new byte[] {2}).getResult());
    assertEquals(result1, cache.getEntryForDecrypt(new byte[] {1}).getResult());
  }

  @Test
  public void whenManyDecryptEntriesAdded_LRURespected() {
    DecryptionMaterials[] results = new DecryptionMaterials[6];

    for (int i = 0; i < results.length; i++) {
      results[i] = CacheTestFixtures.createDecryptResult(CacheTestFixtures.createDecryptRequest(i));
    }

    cache.putEntryForDecrypt(new byte[] {0}, results[0], hint);
    cache.putEntryForDecrypt(new byte[] {1}, results[1], hint);
    cache.putEntryForDecrypt(new byte[] {2}, results[2], hint);
    cache.putEntryForDecrypt(new byte[] {3}, results[3], hint);
    cache.putEntryForDecrypt(new byte[] {4}, results[4], hint);

    // make entry 0 most recently used
    assertEquals(results[0], cache.getEntryForDecrypt(new byte[] {0}).getResult());

    // entry 1 is evicted
    cache.putEntryForDecrypt(new byte[] {5}, results[5], hint);

    for (int i = 0; i < results.length; i++) {
      DecryptionMaterials actualResult =
          Optional.ofNullable(cache.getEntryForDecrypt(new byte[] {(byte) i}))
              .map(CryptoMaterialsCache.DecryptCacheEntry::getResult)
              .orElse(null);
      DecryptionMaterials expected = (i == 1) ? null : results[i];

      assertEquals("index " + i, expected, actualResult);
    }
  }

  @Test
  public void whenEncryptEntriesAdded_theyCanBeRetrieved() {
    EncryptionMaterials result1a =
        CacheTestFixtures.createMaterialsResult(CacheTestFixtures.createMaterialsRequest(0));
    EncryptionMaterials result1b =
        CacheTestFixtures.createMaterialsResult(CacheTestFixtures.createMaterialsRequest(0));
    EncryptionMaterials result2 =
        CacheTestFixtures.createMaterialsResult(CacheTestFixtures.createMaterialsRequest(1));

    cache.putEntryForEncrypt(new byte[] {0}, result1a, hint, UsageStats.ZERO);
    cache.putEntryForEncrypt(new byte[] {0}, result1b, hint, UsageStats.ZERO);
    cache.putEntryForEncrypt(new byte[] {1}, result2, hint, UsageStats.ZERO);

    assertEncryptEntry(new byte[] {0}, result1b);
    assertEncryptEntry(new byte[] {1}, result2);
  }

  @Test
  public void whenInitialUsagePassed_itIsRetained() {
    UsageStats stats = new UsageStats(123, 456);
    EncryptionMaterials result1a =
        CacheTestFixtures.createMaterialsResult(CacheTestFixtures.createMaterialsRequest(0));
    cache.putEntryForEncrypt(new byte[] {0}, result1a, hint, stats);

    assertEquals(stats, cache.getEntryForEncrypt(new byte[] {0}, UsageStats.ZERO).getUsageStats());
  }

  @Test
  public void whenManyEncryptEntriesAdded_LRUIsRespected() {
    EncryptionMaterials[] results = new EncryptionMaterials[6];
    for (int i = 0; i < results.length; i++) {
      results[i] =
          CacheTestFixtures.createMaterialsResult(CacheTestFixtures.createMaterialsRequest(i / 3));
      cache.putEntryForEncrypt(new byte[] {(byte) (i)}, results[i], hint, UsageStats.ZERO);
    }

    for (int i = 0; i < results.length; i++) {
      EncryptionMaterials expected = i == 0 ? null : results[i];

      assertEncryptEntry(new byte[] {(byte) i}, expected);
    }
  }

  @Test
  public void whenManyEncryptEntriesAdded_andEntriesTouched_LRUIsRespected() {
    EncryptionMaterials[] results = new EncryptionMaterials[6];
    for (int i = 0; i < 3; i++) {
      results[i] =
          CacheTestFixtures.createMaterialsResult(CacheTestFixtures.createMaterialsRequest(0));
      cache.putEntryForEncrypt(new byte[] {(byte) i}, results[i], hint, UsageStats.ZERO);
    }

    cache.getEntryForEncrypt(new byte[] {0}, UsageStats.ZERO);

    for (int i = 3; i < 6; i++) {
      results[i] =
          CacheTestFixtures.createMaterialsResult(CacheTestFixtures.createMaterialsRequest(0));
      cache.putEntryForEncrypt(new byte[] {(byte) i}, results[i], hint, UsageStats.ZERO);
    }

    assertEncryptEntry(new byte[] {0}, results[0]);
    assertEncryptEntry(new byte[] {1}, null);
    assertEncryptEntry(new byte[] {2}, results[2]);
    assertEncryptEntry(new byte[] {3}, results[3]);
    assertEncryptEntry(new byte[] {4}, results[4]);
    assertEncryptEntry(new byte[] {5}, results[5]);
  }

  @Test
  public void whenManyEncryptEntriesAdded_andEntryInvalidated_LRUIsRespected() {
    EncryptionMaterials[] results = new EncryptionMaterials[6];
    for (int i = 0; i < 3; i++) {
      results[i] =
          CacheTestFixtures.createMaterialsResult(CacheTestFixtures.createMaterialsRequest(0));
      cache.putEntryForEncrypt(new byte[] {(byte) i}, results[i], hint, UsageStats.ZERO);
    }

    cache.getEntryForEncrypt(new byte[] {2}, UsageStats.ZERO).invalidate();

    for (int i = 3; i < 6; i++) {
      results[i] =
          CacheTestFixtures.createMaterialsResult(CacheTestFixtures.createMaterialsRequest(0));
      cache.putEntryForEncrypt(new byte[] {(byte) i}, results[i], hint, UsageStats.ZERO);
    }

    assertEncryptEntry(new byte[] {0}, results[0]);
    assertEncryptEntry(new byte[] {1}, results[1]);
    assertEncryptEntry(new byte[] {2}, null);
    assertEncryptEntry(new byte[] {3}, results[3]);
    assertEncryptEntry(new byte[] {4}, results[4]);
    assertEncryptEntry(new byte[] {5}, results[5]);
  }

  @Test
  public void testCacheEntryBehavior() {
    EncryptionMaterials result = createResult();
    CryptoMaterialsCache.EncryptCacheEntry e =
        cache.putEntryForEncrypt(new byte[] {0}, result, hint, new UsageStats(1, 2));
    assertEquals(clock.now, e.getEntryCreationTime());

    assertEquals(new UsageStats(1, 2), e.getUsageStats());

    CryptoMaterialsCache.EncryptCacheEntry e2 =
        cache.getEntryForEncrypt(new byte[] {0}, new UsageStats(200, 100));
    // Old entry usage is unchanged
    assertEquals(new UsageStats(1, 2), e.getUsageStats());
    assertEquals(new UsageStats(201, 102), e2.getUsageStats());

    e2.invalidate();
    // All EncryptCacheEntry methods should still work after invalidation
    Assert.assertEquals(result, e2.getResult());
    assertEquals(new UsageStats(201, 102), e2.getUsageStats());
  }

  @Test
  public void whenTTLExceeded_encryptEntriesAreEvicted() throws Exception {
    EncryptionMaterials result = createResult();
    cache.putEntryForEncrypt(new byte[] {0}, result, () -> 500, UsageStats.ZERO);
    clock.now += 500;

    assertEncryptEntry(new byte[] {0}, result);
    clock.now += 1;
    assertEncryptEntry(new byte[] {0}, null);

    // Verify that the cache isn't hanging on to memory once it notices the entry is expired
    assertEquals(0, getCacheMap(cache).size());
  }

  @Test
  public void whenManyEntriesExpireAtOnce_expiredEncryptEntriesStillNotReturned() {
    // Our active TTL expiration logic will only remove a certain number of entries per call, make
    // sure that even
    // if we bail out before removing a particular entry, it's still filtered from the return value.
    cache = new LocalCryptoMaterialsCache(200);
    cache.clock = clock;

    for (int i = 0; i < 100; i++) {
      cache.putEntryForEncrypt(new byte[] {(byte) i}, createResult(), () -> 500, UsageStats.ZERO);
    }

    cache.putEntryForEncrypt(new byte[] {(byte) 0xFF}, createResult(), () -> 501, UsageStats.ZERO);
    clock.now += 502;

    assertEncryptEntry(new byte[] {(byte) 0xFF}, null);
  }

  @Test
  public void whenAccessed_encryptEntryTTLNotReset() {
    EncryptionMaterials result = createResult();
    cache.putEntryForEncrypt(new byte[] {0}, result, hint, UsageStats.ZERO);

    clock.now += 1000;
    assertEncryptEntry(new byte[] {0}, result);
    clock.now += 1;
    assertEncryptEntry(new byte[] {0}, null);
  }

  @Test
  public void whenTTLExceeded_decryptEntriesAreEvicted() throws Exception {
    DecryptionMaterials result =
        CacheTestFixtures.createDecryptResult(CacheTestFixtures.createDecryptRequest(0));

    cache.putEntryForDecrypt(new byte[] {0}, result, hint);

    clock.now += 1001;
    assertNull(cache.getEntryForDecrypt(new byte[] {0}));

    // Verify that the cache isn't hanging on to memory once it notices the entry is expired
    assertEquals(0, getCacheMap(cache).size());
  }

  @Test
  public void whenAccessed_decryptEntryTTLNotReset() {
    DecryptionMaterials result =
        CacheTestFixtures.createDecryptResult(CacheTestFixtures.createDecryptRequest(0));

    cache.putEntryForDecrypt(new byte[] {0}, result, hint);

    clock.now += 500;
    assertNotNull(cache.getEntryForDecrypt(new byte[] {0}));
    clock.now += 501;
    assertNull(cache.getEntryForDecrypt(new byte[] {0}));
  }

  @Test
  public void whenManyEntriesExpireAtOnce_expiredDecryptEntriesStillNotReturned() {
    cache = new LocalCryptoMaterialsCache(200);
    cache.clock = clock;

    for (int i = 0; i < 100; i++) {
      cache.putEntryForEncrypt(
          new byte[] {(byte) (i + 1)}, createResult(), () -> 500, UsageStats.ZERO);
    }

    DecryptionMaterials result =
        CacheTestFixtures.createDecryptResult(CacheTestFixtures.createDecryptRequest(0));
    cache.putEntryForDecrypt(new byte[] {0}, result, () -> 501);

    // our encrypt entries will expire first
    clock.now += 502;
    assertNull(cache.getEntryForDecrypt(new byte[] {0}));
  }

  @Test
  public void testDecryptInvalidate() {
    DecryptionMaterials result =
        CacheTestFixtures.createDecryptResult(CacheTestFixtures.createDecryptRequest(0));

    cache.putEntryForDecrypt(new byte[] {0}, result, hint);

    cache.getEntryForDecrypt(new byte[] {0}).invalidate();
    assertNull(cache.getEntryForDecrypt(new byte[] {0}));
  }

  @Test
  public void testDecryptEntryCreationTime() {
    DecryptionMaterials result =
        CacheTestFixtures.createDecryptResult(CacheTestFixtures.createDecryptRequest(0));

    cache.putEntryForDecrypt(new byte[] {0}, result, hint);

    assertEquals(
        clock.timestamp(), cache.getEntryForDecrypt(new byte[] {0}).getEntryCreationTime());
  }

  @Test
  public void whenIdentifiersDifferInLowOrderBytes_theyAreNotConsideredEquivalent()
      throws Exception {
    DecryptionMaterials result =
        CacheTestFixtures.createDecryptResult(CacheTestFixtures.createDecryptRequest(0));

    cache.putEntryForDecrypt(new byte[128], result, hint);

    for (int i = 0; i < 128; i++) {
      byte[] otherIdentifier = new byte[128];
      otherIdentifier[i]++;

      assertNull(cache.getEntryForDecrypt(otherIdentifier));
    }
  }

  @Test
  public void testUsageStatsCtorValidation() {
    assertThrows(() -> new UsageStats(1, -1));
    assertThrows(() -> new UsageStats(-1, 1));
  }

  private EncryptionMaterials createResult() {
    return CacheTestFixtures.createMaterialsResult(CacheTestFixtures.createMaterialsRequest(0));
  }

  private void assertEncryptEntry(byte[] cacheId, EncryptionMaterials expectedResult) {
    CryptoMaterialsCache.EncryptCacheEntry entry =
        cache.getEntryForEncrypt(cacheId, UsageStats.ZERO);
    EncryptionMaterials actual = entry == null ? null : entry.getResult();

    assertEquals(expectedResult, actual);
  }

  private Map getCacheMap(LocalCryptoMaterialsCache cache) throws Exception {
    Field field = LocalCryptoMaterialsCache.class.getDeclaredField("cacheMap");
    field.setAccessible(true);

    return (Map) field.get(cache);
  }

  private static final class FakeClock implements MsClock {
    long now = 0x1_0000_0000L;

    @Override
    public long timestamp() {
      return now;
    }
  }
}
