package com.amazonaws.encryptionsdk.caching;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.caching.CryptoMaterialsCache.UsageStats;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.Test;

public class LocalCryptoMaterialsCacheThreadStormTest {

  /*
   * This test tests the behavior of LocalCryptoMaterialsCache under contention at the cache level.
   * We specifically test:
   *
   * 1. Gets and puts of encrypt and decrypt entries, including entries under the same cache ID for encrypt
   * 2. Invalidations
   * 3. Changes to cache capacity
   *
   * Periodically, we verify that the system state is sane. This is done by inspecting the private members of
   * LocalCryptoMaterialsCache and verifying that all cache entries are in the LRU map.
   */

  // Private member accessors
  private static final Function<LocalCryptoMaterialsCache, HashMap<?, ?>> get_cacheMap;
  private static final Function<LocalCryptoMaterialsCache, TreeSet<?>> get_expirationQueue;

  private static <T, R> Function<T, R> getGetter(Class<T> klass, String fieldName) {
    try {
      Field f = klass.getDeclaredField(fieldName);
      f.setAccessible(true);

      return obj -> {
        try {
          return (R) f.get(obj);
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      };
    } catch (Exception e) {
      throw new Error(e);
    }
  }

  static {
    get_cacheMap = getGetter(LocalCryptoMaterialsCache.class, "cacheMap");
    get_expirationQueue = getGetter(LocalCryptoMaterialsCache.class, "expirationQueue");
  }

  public static void assertConsistent(LocalCryptoMaterialsCache cache) {
    synchronized (cache) {
      HashSet<Object> expirationQueue = new HashSet<>(get_expirationQueue.apply(cache));
      HashSet<Object> cacheMap = new HashSet<>(get_cacheMap.apply(cache).values());

      assertEquals(
          "Cache group entries are inconsistent with expiration queue", cacheMap, expirationQueue);
    }
  }

  LocalCryptoMaterialsCache cache;

  // When barrier request = true, all worker threads will join the barrier twice.
  CyclicBarrier barrier;
  volatile boolean barrierRequest = false;
  CountDownLatch stopRequest = new CountDownLatch(1);

  // Decrypt results that _might_ be returned. Note that due to race conditions in the test itself,
  // we might be
  // missing valid cached values here; if a result is in neither forbiddenKeys nor possibleDecrypts,
  // then we must
  // assume that it's allowed to be returned.
  ConcurrentHashMap<ByteBuffer, ConcurrentHashMap<CacheTestFixtures.SentinelKey, Object>>
      possibleDecrypts = new ConcurrentHashMap<>();

  // The values of the inner map are arbitrary but non-null (we use this effectively like a set)
  ConcurrentHashMap<ByteBuffer, ConcurrentHashMap<CacheTestFixtures.SentinelKey, Object>>
      possibleEncrypts = new ConcurrentHashMap<>();

  // Counters for debugging the test itself. If null, this debug infrastructure is disabled.
  private ConcurrentHashMap<String, AtomicLong> counters = null; // new ConcurrentHashMap<>();

  void inc(String s) {
    if (counters != null) {
      counters.computeIfAbsent(s, ignored -> new AtomicLong(0)).incrementAndGet();
    }
  }

  private static final EncryptionMaterials BASE_ENCRYPT = CacheTestFixtures.createMaterialsResult();
  private static final DecryptionMaterials BASE_DECRYPT =
      CacheTestFixtures.createDecryptResult(CacheTestFixtures.createDecryptRequest(0));

  private void maybeBarrier() {
    if (barrierRequest) {
      try {
        barrier.await();
        barrier.await();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
  }

  // This thread continually adds items to the decrypt cache, logging ones it added.
  // The expectedDecryptMap has multiple items because we don't know if the cache expired the prior
  // one; the
  // decrypt check thread will check and forget/forbid the expected items that were not found.
  public void decryptAddThread() {
    int nItemsBeforeRelax = 200_000;
    int nItems = 0;

    try {
      while (stopRequest.getCount() > 0) {
        maybeBarrier();

        byte[] ref = new byte[3];
        ThreadLocalRandom.current().nextBytes(ref);
        ref[0] = 0;

        CacheTestFixtures.SentinelKey key = new CacheTestFixtures.SentinelKey();
        DecryptionMaterials result =
            BASE_DECRYPT.toBuilder()
                .setDataKey(
                    new DataKey(
                        key, new byte[0], new byte[0], BASE_DECRYPT.getDataKey().getMasterKey()))
                .build();

        ConcurrentHashMap<CacheTestFixtures.SentinelKey, Object> expectedDecryptMap =
            possibleDecrypts.computeIfAbsent(
                ByteBuffer.wrap(ref), ignored -> new ConcurrentHashMap<>());

        synchronized (expectedDecryptMap) {
          cache.putEntryForDecrypt(ref, result, () -> Long.MAX_VALUE);
          expectedDecryptMap.put(key, this);
        }

        inc("decrypt put");

        if (++nItems >= nItemsBeforeRelax) {
          Thread.sleep(5);
          nItems = 0;
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // The decrypt check thread verifies that the decrypt results are sane - specifically, if we don't
  // see an item
  // that is known to have once been added to the cache, we should not see it reappear later.
  public void decryptCheckThread() {
    try {
      while (stopRequest.getCount() > 0) {
        maybeBarrier();

        byte[] ref = new byte[3];
        ThreadLocalRandom.current().nextBytes(ref);
        ref[0] = 0;

        ConcurrentHashMap<CacheTestFixtures.SentinelKey, Object> expectedDecryptMap =
            possibleDecrypts.computeIfAbsent(
                ByteBuffer.wrap(ref), ignored -> new ConcurrentHashMap<>());

        synchronized (expectedDecryptMap) {
          CryptoMaterialsCache.DecryptCacheEntry result = cache.getEntryForDecrypt(ref);

          CacheTestFixtures.SentinelKey cachedKey = null;
          if (result != null) {
            inc("decrypt: hit");
            cachedKey = (CacheTestFixtures.SentinelKey) result.getResult().getDataKey().getKey();
            if (expectedDecryptMap.containsKey(cachedKey)) {
              inc("decrypt: found key in expected");
            } else {
              fail("decrypt: unexpected key");
            }
          } else {
            inc("decrypt: miss");
          }

          for (CacheTestFixtures.SentinelKey expectedKey : expectedDecryptMap.keySet()) {
            if (cachedKey != expectedKey) {
              inc("decrypt: prune");
              expectedDecryptMap.remove(expectedKey);
            }
          }
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // Continually adds encryption cache entries.
  public void encryptAddThread() {
    int nItemsBeforeRelax = 200_000;
    int nItems = 0;

    try {
      while (stopRequest.getCount() > 0) {
        maybeBarrier();

        byte[] ref = new byte[2];
        ThreadLocalRandom.current().nextBytes(ref);

        EncryptionMaterials result =
            BASE_ENCRYPT.toBuilder()
                .setCleartextDataKey(new CacheTestFixtures.SentinelKey())
                .build();
        ConcurrentHashMap<CacheTestFixtures.SentinelKey, Object> keys =
            possibleEncrypts.computeIfAbsent(
                ByteBuffer.wrap(ref), ignored -> new ConcurrentHashMap<>());
        synchronized (keys) {
          inc("encrypt: add");

          cache.putEntryForEncrypt(ref, result, () -> Long.MAX_VALUE, UsageStats.ZERO);
          keys.put((CacheTestFixtures.SentinelKey) result.getCleartextDataKey(), this);
        }

        if (++nItems >= nItemsBeforeRelax) {
          Thread.sleep(5);
          nItems = 0;
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // Verifies that there is no resurrection, as above.
  public void encryptCheckThread() {
    try {
      while (stopRequest.getCount() > 0) {
        maybeBarrier();

        byte[] ref = new byte[2];
        ThreadLocalRandom.current().nextBytes(ref);

        ConcurrentHashMap<CacheTestFixtures.SentinelKey, Object> allowedKeys =
            possibleEncrypts.computeIfAbsent(
                ByteBuffer.wrap(ref), ignored -> new ConcurrentHashMap<>());

        synchronized (allowedKeys) {
          HashSet<CacheTestFixtures.SentinelKey> foundKeys = new HashSet<>();
          CryptoMaterialsCache.EncryptCacheEntry ece =
              cache.getEntryForEncrypt(ref, UsageStats.ZERO);

          if (ece != null) {
            foundKeys.add((CacheTestFixtures.SentinelKey) ece.getResult().getCleartextDataKey());
          }

          if (foundKeys.isEmpty()) {
            inc("encrypt check: empty foundRefs");
          } else {
            inc("encrypt check: non-empty foundRefs");
          }

          foundKeys.forEach(
              foundKey -> {
                if (!allowedKeys.containsKey(foundKey)) {
                  fail("encrypt check: unexpected key; " + allowedKeys + " " + foundKeys);
                }
              });

          allowedKeys
              .keySet()
              .forEach(
                  allowedKey -> {
                    if (!foundKeys.contains(allowedKey)) {
                      inc("encrypt check: prune");
                      // safe since this is a concurrent map
                      allowedKeys.remove(allowedKey);
                    }
                  });
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // Performs a consistency check of the cache entries vs the LRU tracker periodically. Due to the
  // high overhead
  // of this test, we run it infrequently.
  public void checkThread() {
    try {
      while (!stopRequest.await(5000, TimeUnit.MILLISECONDS)) {
        barrierRequest = true;
        barrier.await();

        assertConsistent(cache);
        inc("consistency check passed");

        barrier.await();
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void test() throws Exception {
    cache = new LocalCryptoMaterialsCache(100_000);

    ArrayList<CompletableFuture<?>> futures = new ArrayList<>();
    ExecutorService es = Executors.newCachedThreadPool();

    ArrayList<Supplier<CompletableFuture<?>>> starters = new ArrayList<>();

    for (int i = 0; i < 2; i++) {
      starters.add(() -> CompletableFuture.runAsync(this::encryptAddThread, es));
      starters.add(() -> CompletableFuture.runAsync(this::encryptCheckThread, es));
      starters.add(() -> CompletableFuture.runAsync(this::decryptAddThread, es));
      starters.add(() -> CompletableFuture.runAsync(this::decryptCheckThread, es));
    }
    starters.add(() -> CompletableFuture.runAsync(this::checkThread, es));

    barrier = new CyclicBarrier(starters.size());

    try {
      starters.forEach(s -> futures.add(s.get()));

      CompletableFuture<?> metaFuture =
          CompletableFuture.anyOf(futures.toArray(new CompletableFuture[0]));

      try {
        metaFuture.get(10, TimeUnit.SECONDS);
        fail("unexpected termination");
      } catch (TimeoutException e) {
        // ok
      }
    } finally {
      stopRequest.countDown();
      es.shutdownNow();

      es.awaitTermination(1, TimeUnit.SECONDS);

      if (counters != null) {
        new TreeMap<>(counters)
            .forEach((k, v) -> System.out.println(String.format("%s: %d", k, v.get())));
      }
    }
  }
}
