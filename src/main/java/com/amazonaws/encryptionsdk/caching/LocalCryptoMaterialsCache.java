package com.amazonaws.encryptionsdk.caching;

import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.TreeSet;
import javax.annotation.concurrent.GuardedBy;

/**
 * A simple implementation of the {@link CryptoMaterialsCache} using a basic LRU cache.
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * LocalCryptoMaterialsCache cache = new LocalCryptoMaterialsCache(500);
 *
 * CachingCryptoMaterialsManager materialsManager = CachingCryptoMaterialsManager.builder()
 *      .setMaxAge(5, TimeUnit.MINUTES)
 *      .setCache(cache)
 *      .withMasterKeyProvider(myMasterKeyProvider)
 *      .build();
 *
 * byte[] data = new AwsCrypto().encryptData(materialsManager, plaintext).getResult();
 * }</pre>
 */
public class LocalCryptoMaterialsCache implements CryptoMaterialsCache {
  // The maximum number of entries to implicitly prune per access due to TTL expiration. We limit
  // this to avoid
  // latency spikes when a large number of entries have expired since the last cache usage.
  private static final int MAX_TTL_PRUNE = 10;

  // Mockable time source, to allow us to test TTL pruning.
  // package access for tests
  // note: we're not using the java 8 time APIs in order to improve android compatibility
  MsClock clock = MsClock.WALLCLOCK;

  // The magic numbers here are the normal defaults for LinkedHashMap; we have to specify them
  // explicitly if we are to
  // specify accessOrder=true, which enables LRU behavior
  private final LinkedHashMap<CacheIdentifier, BaseEntry> cacheMap =
      new LinkedHashMap<>(/* capacity */ 16, /* loadFactor */ 0.75f, /* accessOrder */ true);

  // This is a treeset sorted by TTL to allow us to quickly find expired entries
  private final TreeSet<BaseEntry> expirationQueue =
      new TreeSet<>(LocalCryptoMaterialsCache::compareEntries);

  private final int capacity;

  public LocalCryptoMaterialsCache(int capacity) {
    this.capacity = capacity;
  }

  private static int compareEntries(BaseEntry a, BaseEntry b) {
    int result;

    if (a == b) {
      return 0;
    }

    result = Long.compare(a.expirationTimestamp_, b.expirationTimestamp_);
    if (result != 0) {
      return result;
    }

    return Utils.compareObjectIdentity(a, b);
  }

  /** A common base for both encrypt and decrypt entries */
  private class BaseEntry {
    final CacheIdentifier identifier_;
    final long expirationTimestamp_;
    final long creationTime = clock.timestamp();

    private BaseEntry(CacheIdentifier identifier, long expiration) {
      this.identifier_ = identifier;
      this.expirationTimestamp_ = expiration;
    }
  }

  /** This wrapper just gives us a usable hashcode over our cache identifiers. */
  private static final class CacheIdentifier {
    private final byte[] identifier;
    private final int hashCode;

    private CacheIdentifier(byte[] passed_id) {
      this.identifier = passed_id.clone();
      this.hashCode = Arrays.hashCode(passed_id);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      return Arrays.equals(identifier, ((CacheIdentifier) o).identifier);
    }

    @Override
    public int hashCode() {
      return hashCode;
    }
  }

  // Note: We take locks on both cache entries as well as the overall cache.
  // The lock order is overall cache -> cache entry; this means that the entry cannot call back into
  // the parent cache
  // while holding its own lock.
  private final class EncryptCacheEntryInternal extends BaseEntry {
    private final EncryptionMaterials result;

    @GuardedBy("this")
    private UsageStats usageStats = UsageStats.ZERO;

    private EncryptCacheEntryInternal(
        CacheIdentifier identifier, long expiration, EncryptionMaterials result) {
      super(identifier, expiration);

      this.result = result;
    }

    synchronized UsageStats addAndGetUsageStats(UsageStats delta) {
      this.usageStats = this.usageStats.add(delta);

      return this.usageStats;
    }
  }

  // When returning cache entries, we create a new object to represent the snapshot of usage stats
  // at time of get.
  // This helps avoid races where two gets together push an entry over usage limits, and then both
  // miss when they
  // see the entry over the limit.
  //
  // Not static as invalidate calls back into the cache.
  private final class EncryptCacheEntryExposed implements EncryptCacheEntry {
    private final UsageStats usageStats_;
    private final EncryptCacheEntryInternal internal_;

    private EncryptCacheEntryExposed(
        final UsageStats usageStats, final EncryptCacheEntryInternal internal) {
      usageStats_ = usageStats;
      internal_ = internal;
    }

    @Override
    public UsageStats getUsageStats() {
      return usageStats_;
    }

    @Override
    public long getEntryCreationTime() {
      return internal_.creationTime;
    }

    @Override
    public EncryptionMaterials getResult() {
      return internal_.result;
    }

    @Override
    public void invalidate() {
      removeEntry(internal_);
    }
  }

  private final class DecryptCacheEntryInternal extends BaseEntry implements DecryptCacheEntry {
    final DecryptionMaterials result;

    private DecryptCacheEntryInternal(
        CacheIdentifier identifier, long expiration, DecryptionMaterials result) {
      super(identifier, expiration);

      this.result = result;
    }

    @Override
    public DecryptionMaterials getResult() {
      return result;
    }

    @Override
    public void invalidate() {
      removeEntry(this);
    }

    @Override
    public long getEntryCreationTime() {
      return creationTime;
    }
  }

  /**
   * Removes an entry from the cache.
   *
   * @param e the entry to remove
   */
  private synchronized void removeEntry(BaseEntry e) {
    expirationQueue.remove(e);
    // This does not update the LRU if the value does not match
    cacheMap.remove(e.identifier_, e);
  }

  /** Prunes all TTL-expired entries, plus LRU entries until we are under capacity limits. */
  private synchronized void prune() {
    // Purge maxage-expired entries first, to avoid pruning entries by LRU unnecessarily when we're
    // about to free
    // up space anyway.
    ttlPrune();

    while (cacheMap.size() > capacity) {
      removeEntry(cacheMap.values().iterator().next());
    }
  }

  /** Prunes all TTL-expired entries. Does not check capacity. */
  private void ttlPrune() {
    int pruneCount = 0;
    long now = clock.timestamp();

    while (!expirationQueue.isEmpty()
        && expirationQueue.first().expirationTimestamp_ < now
        && pruneCount < MAX_TTL_PRUNE) {
      removeEntry(expirationQueue.first());
      pruneCount++;
    }
  }

  private synchronized <T extends BaseEntry> T getEntry(Class<T> klass, byte[] identifier) {
    // Perform cache maintenance first
    ttlPrune();

    BaseEntry e = cacheMap.get(new CacheIdentifier(identifier));

    if (e == null) {
      return null;
    } else {
      if (e.expirationTimestamp_ < clock.timestamp()) {
        removeEntry(e);
        return null;
      }

      return klass.cast(e);
    }
  }

  private synchronized void putEntry(final BaseEntry entry) {
    BaseEntry oldEntry = cacheMap.put(entry.identifier_, entry);

    if (oldEntry != null) {
      expirationQueue.remove(oldEntry);
    }
    expirationQueue.add(entry);

    prune();
  }

  @Override
  public EncryptCacheEntry getEntryForEncrypt(byte[] cacheId, final UsageStats usageIncrement) {
    EncryptCacheEntryInternal entry = getEntry(EncryptCacheEntryInternal.class, cacheId);

    if (entry != null) {
      UsageStats stats = entry.addAndGetUsageStats(usageIncrement);
      return new EncryptCacheEntryExposed(stats, entry);
    }

    return null;
  }

  @Override
  public EncryptCacheEntry putEntryForEncrypt(
      byte[] cacheId,
      EncryptionMaterials encryptionMaterials,
      CacheHint hint,
      UsageStats initialUsage) {
    EncryptCacheEntryInternal entry =
        new EncryptCacheEntryInternal(
            new CacheIdentifier(cacheId),
            Utils.saturatingAdd(clock.timestamp(), hint.getMaxAgeMillis()),
            encryptionMaterials);

    entry.addAndGetUsageStats(initialUsage);

    putEntry(entry);

    return new EncryptCacheEntryExposed(initialUsage, entry);
  }

  @Override
  public DecryptCacheEntry getEntryForDecrypt(byte[] cacheId) {
    return getEntry(DecryptCacheEntryInternal.class, cacheId);
  }

  @Override
  public void putEntryForDecrypt(
      byte[] cacheId, DecryptionMaterials decryptionMaterials, CacheHint hint) {
    DecryptCacheEntryInternal entry =
        new DecryptCacheEntryInternal(
            new CacheIdentifier(cacheId),
            Utils.saturatingAdd(clock.timestamp(), hint.getMaxAgeMillis()),
            decryptionMaterials);

    putEntry(entry);
  }
}
