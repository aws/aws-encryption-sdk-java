package com.amazonaws.encryptionsdk.caching;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.DefaultCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.internal.EncryptionContextSerializer;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * The CachingCryptoMaterialsManager wraps another {@link CryptoMaterialsManager}, and caches its
 * results. This helps reduce the number of calls made to the underlying {@link
 * CryptoMaterialsManager} and/or {@link MasterKeyProvider}, which may help reduce cost and/or
 * improve performance.
 *
 * <p>The CachingCryptoMaterialsManager helps enforce a number of usage limits on encrypt.
 * Specifically, it limits the number of individual messages encrypted with a particular data key,
 * and the number of plaintext bytes encrypted with the same data key. It also allows you to
 * configure a maximum time-to-live for cache entries.
 *
 * <p>Note that when performing streaming encryption operations, unless you set the stream size
 * before writing any data using {@link
 * com.amazonaws.encryptionsdk.CryptoOutputStream#setMaxInputLength(long)} or {@link
 * com.amazonaws.encryptionsdk.CryptoInputStream#setMaxInputLength(long)}, the size of the message
 * will not be known, and to avoid exceeding byte use limits, caching will not be performed.
 *
 * <p>By default, two different {@link CachingCryptoMaterialsManager}s will not share cached
 * entries, even when using the same {@link CryptoMaterialsCache}. However, it's possible to make
 * different {@link CachingCryptoMaterialsManager}s share the same cached entries by assigning a
 * partition ID to them; all {@link CachingCryptoMaterialsManager}s with the same partition ID will
 * share the same cached entries.
 *
 * <p>Assigning partition IDs manually requires great care; if the backing {@link
 * CryptoMaterialsManager}s are not equivalent, having entries cross over between them can result in
 * problems such as encrypting messages to the wrong key, or accidentally bypassing access controls.
 * For this reason we recommend not supplying a partition ID unless required for your use case.
 */
public class CachingCryptoMaterialsManager implements CryptoMaterialsManager {
  private static final String CACHE_ID_HASH_ALGORITHM = "SHA-512";
  private static final long MAX_MESSAGE_USE_LIMIT = 1L << 32;
  private static final long MAX_BYTE_USE_LIMIT = Long.MAX_VALUE; // 2^63 - 1

  private final CryptoMaterialsManager backingCMM;
  private final CryptoMaterialsCache cache;

  private final byte[] partitionIdHash;
  private final String partitionId;

  private final long maxAgeMs;
  private final long messageUseLimit;
  private final long byteUseLimit;

  private final CryptoMaterialsCache.CacheHint hint =
      new CryptoMaterialsCache.CacheHint() {
        @Override
        public long getMaxAgeMillis() {
          return maxAgeMs;
        }
      };

  public static class Builder {
    private CryptoMaterialsManager backingCMM;
    private CryptoMaterialsCache cache;
    private String partitionId = null;
    private long maxAge = 0;
    private long messageUseLimit = MAX_MESSAGE_USE_LIMIT;
    private long byteUseLimit = Long.MAX_VALUE;

    private Builder() {}

    /**
     * Sets the {@link CryptoMaterialsManager} that should be queried when the {@link
     * CachingCryptoMaterialsManager} (CCMM) incurs a cache miss.
     *
     * <p>You can set either a MasterKeyProvider or a CryptoMaterialsManager to back the CCMM - the
     * last value set will be used.
     *
     * @param backingCMM The CryptoMaterialsManager to invoke on cache misses
     * @return this builder
     */
    public Builder withBackingMaterialsManager(CryptoMaterialsManager backingCMM) {
      this.backingCMM = backingCMM;
      return this;
    }

    /**
     * Sets the {@link MasterKeyProvider} that should be queried when the {@link
     * CachingCryptoMaterialsManager} (CCMM) incurs a cache miss.
     *
     * <p>You can set either a MasterKeyProvider or a CryptoMaterialsManager to back the CCMM - the
     * last value set will be used.
     *
     * <p>This method is equivalent to calling {@link
     * #withBackingMaterialsManager(CryptoMaterialsManager)} passing a {@link
     * DefaultCryptoMaterialsManager} constructed using your {@link MasterKeyProvider}.
     *
     * @param mkp The MasterKeyProvider to invoke on cache misses
     * @return this builder
     */
    public Builder withMasterKeyProvider(MasterKeyProvider mkp) {
      return withBackingMaterialsManager(new DefaultCryptoMaterialsManager(mkp));
    }

    /**
     * Sets the cache to which this {@link CryptoMaterialsManager} will be bound.
     *
     * @param cache The cache to associate with the CMM
     * @return this builder
     */
    public Builder withCache(CryptoMaterialsCache cache) {
      this.cache = cache;
      return this;
    }

    /**
     * Sets the partition ID for this CMM. This is an optional operation.
     *
     * <p>By default, two CMMs will never use each other's cache entries. This helps ensure that
     * CMMs with different delegates won't incorrectly use each other's encrypt and decrypt results.
     * However, in certain special circumstances it can be useful to share entries between different
     * CMMs - for example, if the backing CMM is constructed based on some parameters that depend on
     * the operation, you may wish for delegates constructed with the same parameters to share the
     * same partition.
     *
     * <p>To accomplish this, set the same partition ID and backing cache on both CMMs; entries
     * cached from one of these CMMs can then be used by the other. This should only be done with
     * careful consideration and verification that the CMM delegates are equivalent for your
     * application's purposes.
     *
     * <p>By default, the partition ID is set to a random UUID to avoid any collisions.
     *
     * @param partitionId The partition ID
     * @return this builder
     */
    public Builder withPartitionId(String partitionId) {
      this.partitionId = partitionId;
      return this;
    }

    /**
     * Sets the maximum lifetime for entries in the cache, for both encrypt and decrypt operations.
     * When the specified amount of time passes after initial creation of the entry, the entry will
     * be considered unusable, and the next operation will incur a cache miss.
     *
     * @param maxAge The amount of time entries are allowed to live. Must be positive.
     * @param units The units maxAge is expressed in
     * @return this builder
     */
    public Builder withMaxAge(long maxAge, TimeUnit units) {
      if (maxAge <= 0) {
        throw new IllegalArgumentException("Max age must be positive");
      }

      this.maxAge = units.toMillis(maxAge);
      return this;
    }

    /**
     * Sets the maximum number of individual messages that can be encrypted under the same a cached
     * data key. This does not affect decrypt operations.
     *
     * <p>Specifying this limit is optional; by default, the limit is set to 2^32. This is also the
     * maximum accepted value; if you specify a higher limit, an {@link IllegalArgumentException}
     * will be thrown.
     *
     * @param messageUseLimit The maximum number of messages that can be encrypted by the same data
     *     key. Must be positive.
     * @return this builder
     */
    public Builder withMessageUseLimit(long messageUseLimit) {
      if (messageUseLimit <= 0) {
        throw new IllegalArgumentException("Message use limit must be positive");
      }

      if (messageUseLimit > MAX_MESSAGE_USE_LIMIT) {
        throw new IllegalArgumentException(
            "Message use limit exceeds limit of " + MAX_MESSAGE_USE_LIMIT);
      }

      // We limit the number of messages encrypted under the same data key primarily to stay far
      // away from any
      // chance of message ID collisions (and therefore collisions of the key+IV used for the actual
      // message
      // encryption).
      this.messageUseLimit = messageUseLimit;
      return this;
    }

    /**
     * Sets the maximum number of plaintext bytes that can be encrypted under the same a cached data
     * key. This does not affect decrypt operations.
     *
     * <p>Specifying this limit is optional; by default, the limit is set to 2^63 - 1.
     *
     * <p>While this limit can be set to zero, in this case keys can only be cached if they are used
     * for zero-length messages.
     *
     * @param byteUseLimit The maximum number of bytes that can be encrypted by the same data key.
     *     Must be non-negative.
     * @return this builder
     */
    public Builder withByteUseLimit(long byteUseLimit) {
      if (byteUseLimit < 0) {
        throw new IllegalArgumentException("Byte use limit must be non-negative");
      }

      // Currently, since the byte use limit is Long.MAX_VALUE, this can't be reached, but is
      // included for
      // consistency.

      //noinspection ConstantConditions
      if (byteUseLimit > MAX_BYTE_USE_LIMIT) {
        throw new IllegalArgumentException(
            "Byte use limit exceeds maximum of " + MAX_BYTE_USE_LIMIT);
      }

      this.byteUseLimit = byteUseLimit;
      return this;
    }

    public CachingCryptoMaterialsManager build() {
      if (backingCMM == null) {
        throw new IllegalArgumentException("Backing CMM must be set");
      }

      if (cache == null) {
        throw new IllegalArgumentException("Cache must be set");
      }

      if (maxAge <= 0) {
        throw new IllegalArgumentException("Max age must be set");
      }

      return new CachingCryptoMaterialsManager(this);
    }
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  private CachingCryptoMaterialsManager(Builder builder) {
    this.backingCMM = builder.backingCMM;
    this.cache = builder.cache;
    this.partitionId =
        builder.partitionId != null ? builder.partitionId : UUID.randomUUID().toString();
    this.maxAgeMs = builder.maxAge;
    this.messageUseLimit = builder.messageUseLimit;
    this.byteUseLimit = builder.byteUseLimit;

    try {
      this.partitionIdHash =
          MessageDigest.getInstance(CACHE_ID_HASH_ALGORITHM)
              .digest(partitionId.getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException e) {
      throw new AwsCryptoException(e);
    }
  }

  @Override
  public EncryptionMaterials getMaterialsForEncrypt(EncryptionMaterialsRequest request) {
    // We cannot correctly enforce size limits if the request has no known plaintext size, so bypass
    // the cache in
    // this case.
    if (request.getPlaintextSize() == -1) {
      return backingCMM.getMaterialsForEncrypt(request);
    }

    // Strip off information on the plaintext length & contents - we do this because we will be
    // (potentially)
    // reusing the result from the backing CMM across multiple requests, and as such it would be
    // misleading to pass on
    // the first such request's information to the backing CMM.

    EncryptionMaterialsRequest upstreamRequest =
        request.toBuilder().setPlaintext(null).setPlaintextSize(-1).build();

    byte[] cacheId = getCacheIdentifier(upstreamRequest);

    CryptoMaterialsCache.UsageStats increment = initialIncrementForRequest(request);

    // If our plaintext size is such that even a brand new entry would reach or exceed cache limits,
    // there's no
    // point in accessing the cache - in fact, doing so would poison a cache entry that could
    // potentially be still
    // used for a smaller request. So we'll bypass the cache and just call the backing CMM directly
    // in this case.
    if (increment.getBytesEncrypted() >= byteUseLimit) {
      return backingCMM.getMaterialsForEncrypt(request);
    }

    CryptoMaterialsCache.EncryptCacheEntry entry = cache.getEntryForEncrypt(cacheId, increment);
    if (entry != null
        && !isEntryExpired(entry.getEntryCreationTime())
        && !hasExceededLimits(entry.getUsageStats())) {
      return entry.getResult();
    } else if (entry != null) {
      // entry has potentially expired, so hint to the cache that it should be removed, in case the
      // cache stores
      // multiple entries or something
      entry.invalidate();
    }

    // Cache miss.
    EncryptionMaterials result = backingCMM.getMaterialsForEncrypt(request);

    if (result.getAlgorithm().isSafeToCache()) {
      cache.putEntryForEncrypt(cacheId, result, hint, initialIncrementForRequest(request));
    }

    return result;
  }

  private boolean hasExceededLimits(final CryptoMaterialsCache.UsageStats stats) {
    return stats.getBytesEncrypted() > byteUseLimit
        || stats.getMessagesEncrypted() > messageUseLimit;
  }

  private boolean isEntryExpired(final long entryCreationTime) {
    return System.currentTimeMillis() - entryCreationTime > maxAgeMs;
  }

  private CryptoMaterialsCache.UsageStats initialIncrementForRequest(
      EncryptionMaterialsRequest request) {
    return new CryptoMaterialsCache.UsageStats(request.getPlaintextSize(), 1);
  }

  @Override
  public DecryptionMaterials decryptMaterials(DecryptionMaterialsRequest request) {
    byte[] cacheId = getCacheIdentifier(request);

    CryptoMaterialsCache.DecryptCacheEntry entry = cache.getEntryForDecrypt(cacheId);

    if (entry != null && !isEntryExpired(entry.getEntryCreationTime())) {
      return entry.getResult();
    }

    DecryptionMaterials result = backingCMM.decryptMaterials(request);
    cache.putEntryForDecrypt(cacheId, result, hint);

    return result;
  }

  private byte[] getCacheIdentifier(EncryptionMaterialsRequest req) {
    try {
      MessageDigest digest = MessageDigest.getInstance(CACHE_ID_HASH_ALGORITHM);

      digest.update(partitionIdHash);

      CryptoAlgorithm algorithm = req.getRequestedAlgorithm();
      digest.update((byte) (algorithm != null ? 1 : 0));
      if (algorithm != null) {
        updateDigestWithAlgorithm(digest, algorithm);
      }

      digest.update(
          MessageDigest.getInstance(CACHE_ID_HASH_ALGORITHM)
              .digest(EncryptionContextSerializer.serialize(req.getContext())));

      return digest.digest();
    } catch (GeneralSecurityException e) {
      throw new AwsCryptoException(e);
    }
  }

  private byte[] getCacheIdentifier(DecryptionMaterialsRequest req) {
    try {
      MessageDigest digest = MessageDigest.getInstance(CACHE_ID_HASH_ALGORITHM);
      byte[] hashOfContext =
          digest.digest(EncryptionContextSerializer.serialize(req.getEncryptionContext()));

      ArrayList<byte[]> keyBlobHashes = new ArrayList<>(req.getEncryptedDataKeys().size());

      for (KeyBlob blob : req.getEncryptedDataKeys()) {
        keyBlobHashes.add(digest.digest(blob.toByteArray()));
      }
      keyBlobHashes.sort(new Utils.ComparingByteArrays());

      // Now starting the digest of the actual cache identifier
      digest.update(partitionIdHash);
      updateDigestWithAlgorithm(digest, req.getAlgorithm());

      keyBlobHashes.forEach(digest::update);

      // This all-zero sentinel field indicates the end of the key blob hashes.
      digest.update(new byte[digest.getDigestLength()]);
      digest.update(hashOfContext);

      return digest.digest();
    } catch (GeneralSecurityException e) {
      throw new AwsCryptoException(e);
    }
  }

  // Common helper to add the algorithm identifier (in proper big endian order) for both encrypt and
  // decrypt paths.
  private void updateDigestWithAlgorithm(MessageDigest digest, CryptoAlgorithm algorithm) {
    short algId = algorithm.getValue();

    digest.update(new byte[] {(byte) (algId >> 8), (byte) (algId)});
  }
}
