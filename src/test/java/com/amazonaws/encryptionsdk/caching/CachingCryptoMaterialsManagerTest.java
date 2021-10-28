package com.amazonaws.encryptionsdk.caching;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.CryptoMaterialsCache.EncryptCacheEntry;
import com.amazonaws.encryptionsdk.caching.CryptoMaterialsCache.UsageStats;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class CachingCryptoMaterialsManagerTest {
  private static final String PARTITION_ID = "partition ID";
  @Mock private CryptoMaterialsCache cache;
  @Mock private CryptoMaterialsManager delegate;
  private CachingCryptoMaterialsManager cmm;
  private CachingCryptoMaterialsManager.Builder builder;
  private long maxAgeMs = 123456789;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);

    when(cache.putEntryForEncrypt(any(), any(), any(), any()))
        .thenAnswer(
            invocation ->
                entryFor((EncryptionMaterials) invocation.getArguments()[1], UsageStats.ZERO));
    when(delegate.getMaterialsForEncrypt(any()))
        .thenThrow(new RuntimeException("Unexpected invocation"));
    when(delegate.decryptMaterials(any())).thenThrow(new RuntimeException("Unexpected invocation"));

    builder =
        CachingCryptoMaterialsManager.newBuilder()
            .withBackingMaterialsManager(delegate)
            .withCache(cache)
            .withPartitionId(PARTITION_ID)
            .withMaxAge(maxAgeMs, TimeUnit.MILLISECONDS)
            .withByteUseLimit(200)
            .withMessageUseLimit(100);
    cmm = builder.build();
  }

  @Test
  public void whenCacheIsEmpty_performsCacheMiss() throws Exception {
    EncryptionMaterialsRequest request =
        CacheTestFixtures.createMaterialsRequest(0).toBuilder().setPlaintextSize(100).build();
    EncryptionMaterials result = CacheTestFixtures.createMaterialsResult(request);

    EncryptCacheEntry entry = setupForCacheMiss(request, result);

    EncryptionMaterials actualResult = cmm.getMaterialsForEncrypt(request);

    assertEquals(result, actualResult);

    verify(delegate).getMaterialsForEncrypt(request);
    verify(cache).putEntryForEncrypt(any(), any(), any(), eq(new UsageStats(100, 1)));
  }

  @Test
  public void whenCacheMisses_correctHintAndUsagePassed() throws Exception {
    EncryptionMaterialsRequest request =
        CacheTestFixtures.createMaterialsRequest(0).toBuilder().setPlaintextSize(100).build();
    EncryptionMaterials result = CacheTestFixtures.createMaterialsResult(request);

    setupForCacheMiss(request, result);
    cmm.getMaterialsForEncrypt(request);

    ArgumentCaptor<CryptoMaterialsCache.CacheHint> hintCaptor =
        ArgumentCaptor.forClass(CryptoMaterialsCache.CacheHint.class);
    verify(cache).putEntryForEncrypt(any(), any(), hintCaptor.capture(), any());

    assertEquals(maxAgeMs, hintCaptor.getValue().getMaxAgeMillis());
  }

  @Test
  public void whenCacheHasEntry_performsCacheHit() throws Exception {
    EncryptionMaterialsRequest request =
        CacheTestFixtures.createMaterialsRequest(0).toBuilder().setPlaintextSize(100).build();
    EncryptionMaterials result = CacheTestFixtures.createMaterialsResult(request);
    EncryptCacheEntry entry = entryFor(result, UsageStats.ZERO);
    when(cache.getEntryForEncrypt(any(), any())).thenReturn(entry);

    assertEquals(result, cmm.getMaterialsForEncrypt(request));
    verify(delegate, never()).getMaterialsForEncrypt(any());

    ArgumentCaptor<UsageStats> statsCaptor = ArgumentCaptor.forClass(UsageStats.class);
    verify(cache).getEntryForEncrypt(any(), statsCaptor.capture());
    assertEquals(statsCaptor.getValue(), new UsageStats(100, 1));
  }

  @Test
  public void whenAlgorithmIsUncachable_resultNotStoredInCache() throws Exception {
    EncryptionMaterialsRequest request =
        CacheTestFixtures.createMaterialsRequest(0).toBuilder().setPlaintextSize(100).build();
    EncryptionMaterials result =
        CacheTestFixtures.createMaterialsResult(request).toBuilder()
            .setAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_NO_KDF)
            .build();
    setupForCacheMiss(request, result);

    assertEquals(result, cmm.getMaterialsForEncrypt(request));
    verify(cache, never()).putEntryForEncrypt(any(), any(), any(), any());
  }

  @Test
  public void whenInitialUsageExceedsLimit_cacheIsBypassed() throws Exception {
    EncryptionMaterialsRequest request =
        CacheTestFixtures.createMaterialsRequest(0).toBuilder()
            // Even at _exactly_ the byte-use limit, we won't try the cache,
            // because it's unlikely to be useful to leave an entry with zero
            // bytes remaining.
            .setPlaintextSize(200)
            .build();
    EncryptionMaterials result =
        CacheTestFixtures.createMaterialsResult(request).toBuilder()
            .setAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_NO_KDF)
            .build();
    setupForCacheMiss(request, result);

    assertEquals(result, cmm.getMaterialsForEncrypt(request));
    verifyNoMoreInteractions(cache);
  }

  @Test
  public void whenCacheEntryIsExhausted_byMessageLimit_performsCacheMiss() throws Exception {
    EncryptionMaterialsRequest request =
        CacheTestFixtures.createMaterialsRequest(0).toBuilder().setPlaintextSize(100).build();
    EncryptionMaterials cacheHitResult = CacheTestFixtures.createMaterialsResult(request);
    doReturn(CacheTestFixtures.createMaterialsResult(request))
        .when(delegate)
        .getMaterialsForEncrypt(request);

    EncryptCacheEntry entry = entryFor(cacheHitResult, new UsageStats(0, 101));

    when(cache.getEntryForEncrypt(any(), any())).thenReturn(entry);

    EncryptionMaterials returnedResult = cmm.getMaterialsForEncrypt(request);

    assertNotEquals(cacheHitResult, returnedResult);
    verify(delegate, times(1)).getMaterialsForEncrypt(any());
    verify(cache).putEntryForEncrypt(any(), eq(returnedResult), any(), any());
  }

  @Test
  public void whenEncryptCacheEntryIsExpired_performsCacheMiss() throws Exception {
    EncryptionMaterialsRequest request =
        CacheTestFixtures.createMaterialsRequest(0).toBuilder().setPlaintextSize(100).build();
    EncryptionMaterials cacheHitResult = CacheTestFixtures.createMaterialsResult(request);
    doReturn(CacheTestFixtures.createMaterialsResult(request))
        .when(delegate)
        .getMaterialsForEncrypt(request);

    EncryptCacheEntry entry = entryFor(cacheHitResult, new UsageStats(0, 100));
    when(entry.getEntryCreationTime()).thenReturn(System.currentTimeMillis() - maxAgeMs - 1);

    when(cache.getEntryForEncrypt(any(), any())).thenReturn(entry);

    EncryptionMaterials returnedResult = cmm.getMaterialsForEncrypt(request);

    assertNotEquals(cacheHitResult, returnedResult);
    verify(delegate, times(1)).getMaterialsForEncrypt(any());
    verify(cache).putEntryForEncrypt(any(), eq(returnedResult), any(), any());
    verify(entry).invalidate();
  }

  @Test
  public void whenCacheEntryIsExhausted_byByteLimit_performsCacheMiss() throws Exception {
    EncryptionMaterialsRequest request =
        CacheTestFixtures.createMaterialsRequest(0).toBuilder().setPlaintextSize(100).build();
    EncryptionMaterials cacheHitResult = CacheTestFixtures.createMaterialsResult(request);
    doReturn(CacheTestFixtures.createMaterialsResult(request))
        .when(delegate)
        .getMaterialsForEncrypt(request);

    EncryptCacheEntry entry = entryFor(cacheHitResult, new UsageStats(1_000_000 - 99, 0));

    when(cache.getEntryForEncrypt(any(), any())).thenReturn(entry);

    EncryptionMaterials returnedResult = cmm.getMaterialsForEncrypt(request);

    assertNotEquals(cacheHitResult, returnedResult);
    verify(delegate, times(1)).getMaterialsForEncrypt(any());
    verify(cache).putEntryForEncrypt(any(), eq(returnedResult), any(), any());
  }

  @Test
  public void whenStreaming_cacheMiss_withNoSizeHint_doesNotCache() throws Exception {
    EncryptionMaterialsRequest request = CacheTestFixtures.createMaterialsRequest(0);
    EncryptionMaterials result = CacheTestFixtures.createMaterialsResult(request);
    EncryptCacheEntry entry = setupForCacheMiss(request, result);

    EncryptionMaterials actualResult = cmm.getMaterialsForEncrypt(request);

    verifyNoMoreInteractions(cache);
  }

  @Test
  public void whenDecrypting_cacheMiss() throws Exception {
    DecryptionMaterialsRequest request = CacheTestFixtures.createDecryptRequest(0);
    DecryptionMaterials result = CacheTestFixtures.createDecryptResult(request);

    doReturn(result).when(delegate).decryptMaterials(any());

    DecryptionMaterials actual = cmm.decryptMaterials(request);

    assertEquals(result, actual);
    verify(cache).putEntryForDecrypt(any(), eq(result), any());
  }

  @Test
  public void whenDecryptCacheMisses_correctHintPassed() throws Exception {
    DecryptionMaterialsRequest request = CacheTestFixtures.createDecryptRequest(0);
    DecryptionMaterials result = CacheTestFixtures.createDecryptResult(request);

    doReturn(result).when(delegate).decryptMaterials(any());

    cmm.decryptMaterials(request);

    ArgumentCaptor<CryptoMaterialsCache.CacheHint> hintCaptor =
        ArgumentCaptor.forClass(CryptoMaterialsCache.CacheHint.class);
    verify(cache).putEntryForDecrypt(any(), any(), hintCaptor.capture());

    assertEquals(maxAgeMs, hintCaptor.getValue().getMaxAgeMillis());
  }

  @Test
  public void whenDecrypting_cacheHit() throws Exception {
    DecryptionMaterialsRequest request = CacheTestFixtures.createDecryptRequest(0);
    DecryptionMaterials result = CacheTestFixtures.createDecryptResult(request);

    when(cache.getEntryForDecrypt(any())).thenReturn(new TestDecryptCacheEntry(result));

    DecryptionMaterials actual = cmm.decryptMaterials(request);

    assertEquals(result, actual);
    verify(cache, never()).putEntryForDecrypt(any(), any(), any());
    verify(delegate, never()).decryptMaterials(any());
  }

  @Test
  public void whenDecrypting_andEntryExpired_cacheMiss() throws Exception {
    DecryptionMaterialsRequest request = CacheTestFixtures.createDecryptRequest(0);
    DecryptionMaterials result = CacheTestFixtures.createDecryptResult(request);
    doReturn(CacheTestFixtures.createDecryptResult(request)).when(delegate).decryptMaterials(any());

    TestDecryptCacheEntry entry = new TestDecryptCacheEntry(result);
    entry.creationTime -= (maxAgeMs + 1);
    when(cache.getEntryForDecrypt(any())).thenReturn(entry);

    DecryptionMaterials actual = cmm.decryptMaterials(request);

    assertNotEquals(result, actual);
    verify(delegate, times(1)).decryptMaterials(any());
    verify(cache, times(1)).putEntryForDecrypt(any(), any(), any());
  }

  @Test
  public void testBuilderValidation() throws Exception {
    CachingCryptoMaterialsManager.Builder b = CachingCryptoMaterialsManager.newBuilder();

    assertThrows(() -> b.withMaxAge(-1, TimeUnit.MILLISECONDS));
    assertThrows(() -> b.withMaxAge(0, TimeUnit.MILLISECONDS));
    assertThrows(() -> b.withMessageUseLimit(-1));
    assertThrows(() -> b.withMessageUseLimit(1L << 33));
    assertThrows(() -> b.withByteUseLimit(-1));

    assertThrows(b::build); // backing CMM not set
    b.withBackingMaterialsManager(delegate);
    assertThrows(b::build); // cache not set
    b.withCache(cache);
    assertThrows(b::build); // max age
    b.withMaxAge(1, TimeUnit.SECONDS);
    b.build();
  }

  @Test
  public void whenBuilderReused_uniquePartitionSet() throws Exception {
    EncryptionMaterialsRequest request =
        CacheTestFixtures.createMaterialsRequest(0).toBuilder().setPlaintextSize(1).build();
    EncryptionMaterials result = CacheTestFixtures.createMaterialsResult(request);
    EncryptCacheEntry entry = setupForCacheMiss(request, result);

    CachingCryptoMaterialsManager.Builder builder =
        CachingCryptoMaterialsManager.newBuilder()
            .withCache(cache)
            .withBackingMaterialsManager(delegate)
            .withMaxAge(5, TimeUnit.DAYS);

    builder.build().getMaterialsForEncrypt(request);
    builder.build().getMaterialsForEncrypt(request);

    ArgumentCaptor<byte[]> idCaptor = ArgumentCaptor.forClass(byte[].class);
    verify(cache, times(2)).getEntryForEncrypt(idCaptor.capture(), any());

    byte[] firstId = idCaptor.getAllValues().get(0);
    byte[] secondId = idCaptor.getAllValues().get(1);

    assertFalse(Arrays.equals(firstId, secondId));
  }

  @Test
  public void whenMKPPassed_itIsUsed() throws Exception {
    JceMasterKey key =
        spy(
            JceMasterKey.getInstance(
                new SecretKeySpec(new byte[16], "AES"), "provider", "keyId", "AES/GCM/NoPadding"));
    CryptoMaterialsManager cmm =
        CachingCryptoMaterialsManager.newBuilder()
            .withCache(cache)
            .withMasterKeyProvider(key)
            .withMaxAge(5, TimeUnit.DAYS)
            .build();

    cmm.getMaterialsForEncrypt(CacheTestFixtures.createMaterialsRequest(0));
    verify(key).generateDataKey(any(), any());
  }

  private EncryptCacheEntry setupForCacheMiss(
      EncryptionMaterialsRequest request, EncryptionMaterials result) throws Exception {
    doReturn(result).when(delegate).getMaterialsForEncrypt(request);
    EncryptCacheEntry entry = entryFor(result, UsageStats.ZERO);
    doReturn(entry).when(cache).putEntryForEncrypt(any(), eq(result), any(), any());

    return entry;
  }

  private EncryptCacheEntry entryFor(EncryptionMaterials result, final UsageStats initialUsage)
      throws Exception {
    return spy(new TestEncryptCacheEntry(result, initialUsage));
  }

  private static class TestEncryptCacheEntry implements EncryptCacheEntry {
    private final EncryptionMaterials result;
    private final UsageStats stats;

    public TestEncryptCacheEntry(EncryptionMaterials result, UsageStats initialUsage) {
      this.result = result;
      stats = initialUsage;
    }

    @Override
    public UsageStats getUsageStats() {
      return stats;
    }

    @Override
    public long getEntryCreationTime() {
      return System.currentTimeMillis();
    }

    @Override
    public EncryptionMaterials getResult() {
      return result;
    }

    @Override
    public void invalidate() {}
  }

  private class TestDecryptCacheEntry implements CryptoMaterialsCache.DecryptCacheEntry {
    private final DecryptionMaterials result;
    private long creationTime = System.currentTimeMillis();

    public TestDecryptCacheEntry(final DecryptionMaterials result) {
      this.result = result;
    }

    @Override
    public DecryptionMaterials getResult() {
      return result;
    }

    @Override
    public void invalidate() {}

    @Override
    public long getEntryCreationTime() {
      return creationTime;
    }
  }
}
