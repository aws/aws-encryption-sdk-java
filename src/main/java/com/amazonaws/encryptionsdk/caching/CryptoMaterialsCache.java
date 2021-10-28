package com.amazonaws.encryptionsdk.caching;

import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import java.util.Objects;

/**
 * Represents a generic cache for cryptographic materials. MaterialsCaches store mappings from
 * abstract bytestring identifiers to MaterialsResults and DecryptResults.
 *
 * <p>In general, the materials cache is concerned about the proper storage of these materials, and
 * managing size limits on the cache. While it stores statistics about cache usage limits, the
 * enforcement of these limits is left to the caller (typically, a {@link
 * CachingCryptoMaterialsManager}).
 *
 * <p>For encrypt, a cache implementation may store multiple cache entries for the same identifier.
 * This allows for usage limits to be enforced even when doing multiple streaming requests in
 * parallel. However, the cache is permitted to set a limit on the number of such entries (even as
 * low as only allowing one entry per identifier), and if it does so should evict the excess
 * entries.
 *
 * <p>Being a cache, a CryptoMaterialsCache is permitted to evict entries at any time. However, a
 * caller can explicitly hint the cache to invalidate an entry in the encrypt-side cache. This is
 * generally done when usage limits are exceeded. The cache is not required to respect this
 * invalidation hint.
 *
 * <p>Likewise, the CacheHint passed to the put calls on caches will indicate the maximum lifetime
 * of entries; the cache is allowed - but not required - to evict entries automatically upon
 * expiration of this lifetime.
 */
public interface CryptoMaterialsCache {

  /**
   * Searches for an entry in the encrypt cache matching a particular cache identifier, and returns
   * one if found.
   *
   * @param cacheId The identifier for the item in the cache
   * @param usageIncrement The amount of usage to atomically add to the returned entry. This usage
   *     increment must be reflected in the getUsageStats() method on the returned cache entry.
   * @return The entry, or null if not found or an error occurred
   */
  EncryptCacheEntry getEntryForEncrypt(byte[] cacheId, final UsageStats usageIncrement);

  /**
   * Attempts to add a new entry to the encrypt cache to be returned on subsequent {@link
   * #getEntryForEncrypt(byte[], UsageStats)} calls.
   *
   * <p>In the event that an error occurs when adding the entry to the cache, this function shall
   * still return a EncryptCacheEntry instance, which shall act as if the cache entry was
   * immediately evicted and/or invalidated.
   *
   * @param cacheId The identifier for the item in the cache
   * @param encryptionMaterials The {@link EncryptionMaterials} to associate with this new entry
   * @param initialUsage The initial usage stats for the cache entry
   * @return A new, locked EncryptCacheEntry instance containing the given encryptionMaterials
   */
  EncryptCacheEntry putEntryForEncrypt(
      byte[] cacheId,
      EncryptionMaterials encryptionMaterials,
      CacheHint hint,
      UsageStats initialUsage);

  /**
   * Searches for an entry in the encrypt cache matching a particular cache identifier, and returns
   * one if found.
   *
   * <p>In the event of an error accessing the cache, this function will return null.
   *
   * @param cacheId The identifier for the item in the cache
   * @return The cached decryption result, or null if none was found or an error occurred.
   */
  DecryptCacheEntry getEntryForDecrypt(byte[] cacheId);

  /**
   * Adds a new entry to the decrypt cache. In the event of an error, this function will return
   * silently without propagating the exception.
   *
   * <p>If an entry already exists for this cache ID, the cache may either overwrite the entry in
   * its entirety, or update the creation timestamp for the existing entry, at its option.
   *
   * @param cacheId The identifier for the item in the cache
   * @param decryptionMaterials The {@link DecryptionMaterials} to associate with the new entry.
   */
  void putEntryForDecrypt(byte[] cacheId, DecryptionMaterials decryptionMaterials, CacheHint hint);

  /**
   * Contains some additional information associated with a cache entry. The cache receiving this
   * hint may take some actions based on the hint, or it may ignore it entirely.
   */
  interface CacheHint {
    /**
     * Returns the lifetime of the cache entry. This hint suggests to the cache that the entry will
     * not be useful after the provided number of milliseconds passes, and suggests that the cache
     * should discard the entry when this interval elapses even if it is not explicitly invalidated.
     *
     * <p>Note that this time counts from the <i>creation</i> of the entry, not from last use.
     *
     * @return The lifetime of this entry, in milliseconds. If the lifetime is unknown or
     *     irrelevant, this will return {@link Long#MAX_VALUE}.
     */
    long getMaxAgeMillis();
  }

  /**
   * Represents an entry in the encrypt cache, and provides methods for manipulating the entry.
   *
   * <p>Note that the EncryptCacheEntry Java object remains valid even after the cache entry is
   * invalidated or evicted; getResult will still return a valid result, for example.
   */
  interface EncryptCacheEntry {
    /**
     * @return The current usage statistics for this entry. The caller should be aware that these
     *     statistics may be stale by the time they are returned.
     */
    UsageStats getUsageStats();

    /** @return The unix timestamp at which this entry was added to the cache, in milliseconds */
    long getEntryCreationTime();

    /**
     * @return The EncryptionMaterials associated with this cache entry. The encrypt completion
     *     callback should be a no-op.
     */
    EncryptionMaterials getResult();

    /** Suggests to the cache that this entry should be removed from the cache. */
    default void invalidate() {}
  }

  final class UsageStats {
    public static final UsageStats ZERO = new UsageStats(0, 0);

    private final long bytesEncrypted;
    private final long messagesEncrypted;

    public UsageStats(long bytesEncrypted, long messagesEncrypted) {
      if (bytesEncrypted < 0) {
        throw new IllegalArgumentException("Negative bytes encrypted is not permitted");
      }

      if (messagesEncrypted < 0) {
        throw new IllegalArgumentException("Negative messages encrypted is not permitted");
      }

      this.bytesEncrypted = bytesEncrypted;
      this.messagesEncrypted = messagesEncrypted;
    }

    public long getBytesEncrypted() {
      return bytesEncrypted;
    }

    public long getMessagesEncrypted() {
      return messagesEncrypted;
    }

    /**
     * Performs a pairwise add of two UsageStats objects. In the event of overflow, counters
     * saturate at {@link Long#MAX_VALUE}
     *
     * @param other
     * @return
     */
    public UsageStats add(UsageStats other) {
      return new UsageStats(
          saturatingAdd(getBytesEncrypted(), other.getBytesEncrypted()),
          saturatingAdd(getMessagesEncrypted(), other.getMessagesEncrypted()));
    }

    static long saturatingAdd(long a, long b) {
      if (a < 0 || b < 0) {
        throw new IllegalArgumentException("Negative usage values are not permitted");
      }

      return Utils.saturatingAdd(a, b);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      UsageStats that = (UsageStats) o;
      return getBytesEncrypted() == that.getBytesEncrypted()
          && getMessagesEncrypted() == that.getMessagesEncrypted();
    }

    @Override
    public int hashCode() {
      return Objects.hash(getBytesEncrypted(), getMessagesEncrypted());
    }

    @Override
    public String toString() {
      return "UsageStats{"
          + "bytesEncrypted="
          + bytesEncrypted
          + ", messagesEncrypted="
          + messagesEncrypted
          + '}';
    }
  }

  /**
   * Represents an entry in the decrypt cache, and provides methods for manipulating the entry.
   *
   * <p>Note that the DecryptCacheEntry JAva object remains valid even after the cache entry is
   * invalidated or evicted; getResult will still return a valid result, for example.
   */
  interface DecryptCacheEntry {
    /** Returns the DecryptionMaterials associated with this entry. */
    DecryptionMaterials getResult();

    /** Advises the cache that this entry should be removed from the cache. */
    void invalidate();

    /** @return The unix timestamp at which this entry was added to the cache, in milliseconds */
    long getEntryCreationTime();
  }
}
