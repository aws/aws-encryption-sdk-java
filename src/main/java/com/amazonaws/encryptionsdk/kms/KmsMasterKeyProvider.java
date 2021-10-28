// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.Request;
import com.amazonaws.Response;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.MasterKeyRequest;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.internal.AwsKmsCmkArnInfo;
import com.amazonaws.handlers.RequestHandler2;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.RegionUtils;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Provides {@link MasterKey}s backed by the AWS Key Management Service. This object is regional and
 * if you want to use keys from multiple regions, you'll need multiple copies of this object.
 */
public class KmsMasterKeyProvider extends MasterKeyProvider<KmsMasterKey> implements KmsMethods {
  private static final String PROVIDER_NAME = "aws-kms";
  private final List<String> keyIds_;
  private final List<String> grantTokens_;

  private static final boolean IS_DISCOVERY_DEFAULT = true;
  private final boolean isDiscovery_;
  private final DiscoveryFilter discoveryFilter_;

  private final RegionalClientSupplier regionalClientSupplier_;
  private final String defaultRegion_;

  @FunctionalInterface
  public interface RegionalClientSupplier {
    /**
     * Supplies an AWSKMS instance to use for a given region. The {@link KmsMasterKeyProvider} will
     * not cache the result of this function.
     *
     * @param regionName The region to get a client for
     * @return The client to use, or null if this region cannot or should not be used.
     */
    AWSKMS getClient(String regionName);
  }

  public static class Builder implements Cloneable {
    private String defaultRegion_ = null;
    private RegionalClientSupplier regionalClientSupplier_ = null;
    private AWSKMSClientBuilder templateBuilder_ = null;
    private List<String> keyIds_ = new ArrayList<>();
    private boolean isDiscovery_ = IS_DISCOVERY_DEFAULT;
    private DiscoveryFilter discoveryFilter_ = null;

    Builder() {
      // Default access: Don't allow outside classes to extend this class
    }

    public Builder clone() {
      try {
        Builder cloned = (Builder) super.clone();

        if (templateBuilder_ != null) {
          cloned.templateBuilder_ = cloneClientBuilder(templateBuilder_);
        }

        cloned.keyIds_ = new ArrayList<>(keyIds_);

        return cloned;
      } catch (CloneNotSupportedException e) {
        throw new Error("Impossible: CloneNotSupportedException", e);
      }
    }

    /**
     * Adds key ID(s) to the list of keys to use on encryption.
     *
     * @deprecated This method allows for configuring {@code keyIds} for encryption on KMS Master
     *     Key Providers that perform the discovery behavior on decrypt, which results in a complex
     *     behavior mode for the KMS Master Key Provider. Use {@link #buildStrict(List)} to
     *     construct a Master Key Provider that uses the supplied {@code keysIds} for encryption and
     *     decryption. If a KMS Master Key Provider that decrypts with discovery behavior is still
     *     required, use {@link #buildDiscovery()} or {@link #buildDiscovery(DiscoveryFilter)} to
     *     construct a seperate Master Key Provider that is used for decryption.
     * @param keyIds
     * @return
     */
    @Deprecated
    public Builder withKeysForEncryption(String... keyIds) {
      keyIds_.addAll(asList(keyIds));
      return this;
    }

    /**
     * Adds key ID(s) to the list of keys to use on encryption.
     *
     * @deprecated This method allows for configuring {@code keyIds} for encryption on KMS Master
     *     Key Providers that perform the discovery behavior on decrypt, which results in a complex
     *     behavior mode for the KMS Master Key Provider. Use {@link #buildStrict(List)} to
     *     construct a Master Key Provider that uses the supplied {@code keysIds} for encryption and
     *     decryption. If a KMS Master Key Provider that decrypts with discovery behavior is still
     *     required, use {@link #buildDiscovery()} or {@link #buildDiscovery(DiscoveryFilter)} to
     *     construct a seperate Master Key Provider that is used for decryption.
     * @param keyIds
     * @return
     */
    @Deprecated
    public Builder withKeysForEncryption(List<String> keyIds) {
      keyIds_.addAll(keyIds);
      return this;
    }

    /**
     * Sets the default region. This region will be used when specifying key IDs for encryption or
     * in {@link KmsMasterKeyProvider#getMasterKey(String)} that are not full ARNs, but are instead
     * bare key IDs or aliases.
     *
     * <p>If the default region is not specified, only full key ARNs will be usable.
     *
     * @param defaultRegion The default region to use.
     * @return
     */
    public Builder withDefaultRegion(String defaultRegion) {
      this.defaultRegion_ = defaultRegion;
      return this;
    }

    /**
     * Provides a custom factory function that will vend KMS clients. This is provided for advanced
     * use cases which require complete control over the client construction process.
     *
     * <p>Because the regional client supplier fully controls the client construction process, it is
     * not possible to configure the client through methods such as {@link
     * #withCredentials(AWSCredentialsProvider)} or {@link #withClientBuilder(AWSKMSClientBuilder)};
     * if you try to use these in combination, an {@link IllegalStateException} will be thrown.
     *
     * @param regionalClientSupplier
     * @return
     */
    public Builder withCustomClientFactory(RegionalClientSupplier regionalClientSupplier) {
      if (templateBuilder_ != null) {
        throw clientSupplierComboException();
      }

      regionalClientSupplier_ = regionalClientSupplier;
      return this;
    }

    private RuntimeException clientSupplierComboException() {
      return new IllegalStateException(
          "withCustomClientFactory cannot be used in conjunction with "
              + "withCredentials or withClientBuilder");
    }

    /**
     * Configures the {@link KmsMasterKeyProvider} to use specific credentials. If a builder was
     * previously set, this will override whatever credentials it set.
     *
     * @param credentialsProvider
     * @return
     */
    public Builder withCredentials(AWSCredentialsProvider credentialsProvider) {
      if (regionalClientSupplier_ != null) {
        throw clientSupplierComboException();
      }

      if (templateBuilder_ == null) {
        templateBuilder_ = AWSKMSClientBuilder.standard();
      }

      templateBuilder_.setCredentials(credentialsProvider);

      return this;
    }

    /**
     * Configures the {@link KmsMasterKeyProvider} to use specific credentials. If a builder was
     * previously set, this will override whatever credentials it set.
     *
     * @param credentials
     * @return
     */
    public Builder withCredentials(AWSCredentials credentials) {
      return withCredentials(new AWSStaticCredentialsProvider(credentials));
    }

    /**
     * Configures the {@link KmsMasterKeyProvider} to use settings from this {@link
     * AWSKMSClientBuilder} to configure KMS clients. Note that the region set on this builder will
     * be ignored, but all other settings will be propagated into the regional clients.
     *
     * <p>This method will overwrite any credentials set using {@link
     * #withCredentials(AWSCredentialsProvider)}.
     *
     * @param builder
     * @return
     */
    public Builder withClientBuilder(AWSKMSClientBuilder builder) {
      if (regionalClientSupplier_ != null) {
        throw clientSupplierComboException();
      }
      final AWSKMSClientBuilder newBuilder = cloneClientBuilder(builder);

      this.templateBuilder_ = newBuilder;

      return this;
    }

    private AWSKMSClientBuilder cloneClientBuilder(final AWSKMSClientBuilder builder) {
      // We need to copy all arguments out of the builder in case it's mutated later on.
      // Unfortunately AWSKMSClientBuilder doesn't support .clone() so we'll have to do it by hand.

      if (builder.getEndpoint() != null) {
        // We won't be able to set the region later if a custom endpoint is set.
        throw new IllegalArgumentException(
            "Setting endpoint configuration is not compatible with passing a "
                + "builder to the KmsMasterKeyProvider. Use withCustomClientFactory"
                + " instead.");
      }

      final AWSKMSClientBuilder newBuilder = AWSKMSClient.builder();
      newBuilder.setClientConfiguration(builder.getClientConfiguration());
      newBuilder.setCredentials(builder.getCredentials());
      newBuilder.setEndpointConfiguration(builder.getEndpoint());
      newBuilder.setMetricsCollector(builder.getMetricsCollector());
      if (builder.getRequestHandlers() != null) {
        newBuilder.setRequestHandlers(builder.getRequestHandlers().toArray(new RequestHandler2[0]));
      }
      return newBuilder;
    }

    /**
     * Builds the master key provider in Discovery Mode. In Discovery Mode the KMS Master Key
     * Provider will attempt to decrypt using any key identifier it discovers in the encrypted
     * message. KMS Master Key Providers in Discovery Mode will not encrypt data keys.
     *
     * @return
     */
    public KmsMasterKeyProvider buildDiscovery() {
      if (keyIds_.size() > 0) {
        throw new IllegalStateException(
            "Cannot explicitly build Discovery KMS Master Key "
                + "Provider with keyIds configured");
      }
      isDiscovery_ = true;
      return buildBase();
    }

    /**
     * Builds the master key provider in Discovery Mode with a {@link DiscoveryFilter}. In Discovery
     * Mode the KMS Master Key Provider will attempt to decrypt using any key identifier it
     * discovers in the encrypted message that is accepted by the {@code filter}. KMS Master Key
     * Providers in Discovery Mode will not encrypt data keys.
     *
     * @param filter
     * @return
     */
    public KmsMasterKeyProvider buildDiscovery(DiscoveryFilter filter) {
      if (filter == null) {
        throw new IllegalArgumentException(
            "Discovery filter must not be null if specifying " + "a discovery filter.");
      }
      discoveryFilter_ = filter;

      return buildDiscovery();
    }

    /**
     * Builds the master key provider in Strict Mode. KMS Master Key Providers in Strict Mode will
     * only attempt to decrypt using key ARNs listed in {@code keyIds}. KMS Master Key Providers in
     * Strict Mode will encrypt data keys using the keys listed in {@code keyIds}
     *
     * <p>In Strict Mode, one or more CMKs must be provided. For providers that will only be used
     * for encryption, you can use any valid KMS key identifier. For providers that will be used for
     * decryption, you must use the key ARN; key ids, alias names, and alias ARNs are not supported.
     *
     * @param keyIds
     * @return
     */
    public KmsMasterKeyProvider buildStrict(List<String> keyIds) {
      if (keyIds == null) {
        throw new IllegalArgumentException(
            "Strict mode must be configured with a non-empty " + "list of keyIds.");
      }
      if (keyIds_.size() > 0) {
        throw new IllegalStateException(
            "buildStrict cannot be used in conjunction with "
                + "withKeysForEncryption. Please supply keys to encrypt and decrypt with "
                + "to buildStrict()");
      }
      if (keyIds.contains(null)) {
        throw new IllegalArgumentException(
            "Cannot configure Strict KMS Master Key Provider with " + "null key identifier.");
      }

      isDiscovery_ = false;
      keyIds_.addAll(keyIds);
      return buildBase();
    }

    /**
     * Builds the master key provider in strict mode. KMS Master Key Providers in Strict Mode will
     * only attempt to decrypt using key ARNs listed in {@code keyIds}. KMS Master Key Providers in
     * Strict Mode will encrypt data keys using the keys listed in {@code keyIds}
     *
     * <p>In Strict Mode, one or more CMKs must be provided. For providers that will only be used
     * for encryption, you can use any valid KMS key identifier. For providers that will be used for
     * decryption, you must use the key ARN; key ids, alias names, and alias ARNs are not supported.
     *
     * @param keyIds
     * @return
     */
    public KmsMasterKeyProvider buildStrict(String... keyIds) {
      return buildStrict(asList(keyIds));
    }

    /**
     * Builds the master key provider.
     *
     * @deprecated This method implicitly configures the KMS Master Key Provider to perform
     *     discovery behavior on decrypt, which is a behavior that should be constructed explicitly.
     *     To create a KMS Master Key Provider that continues to perform discovery on decrypt, use
     *     {@link #buildDiscovery()} or {@link #buildDiscovery(DiscoveryFilter)}. To create a KMS
     *     Master Key Provider that restricts what keys to attempt decryption with to a set of
     *     configured keys, use {@link #buildStrict(List)}.
     * @return
     */
    @Deprecated
    public KmsMasterKeyProvider build() {
      return buildBase();
    }

    private KmsMasterKeyProvider buildBase() {
      // If we don't have a default region, we need to check that all key IDs will be usable
      if (defaultRegion_ == null) {
        for (String keyId : keyIds_) {
          final AwsKmsCmkArnInfo arnInfo = parseInfoFromKeyArn(keyId);
          if (arnInfo == null) {
            throw new AwsCryptoException(
                "Can't use non-ARN key identifiers or aliases when " + "no default region is set");
          }
        }
      }

      RegionalClientSupplier supplier = clientFactory();

      return new KmsMasterKeyProvider(
          supplier, defaultRegion_, keyIds_, emptyList(), false, isDiscovery_, discoveryFilter_);
    }

    private RegionalClientSupplier clientFactory() {
      if (regionalClientSupplier_ != null) {
        return regionalClientSupplier_;
      }

      // Clone again; this MKP builder might be reused to build a second MKP with different creds.
      AWSKMSClientBuilder builder =
          templateBuilder_ != null
              ? cloneClientBuilder(templateBuilder_)
              : AWSKMSClientBuilder.standard();

      ConcurrentHashMap<String, AWSKMS> clientCache = new ConcurrentHashMap<>();
      snoopClientCache(clientCache);

      return region -> {
        AWSKMS kms = clientCache.get(region);

        if (kms != null) return kms;

        // We can't just use computeIfAbsent as we need to avoid leaking KMS clients if we're asked
        // to decrypt
        // an EDK with a bogus region in its ARN. So we'll install a request handler to identify the
        // first
        // successful call, and cache it when we see that.
        SuccessfulRequestCacher cacher = new SuccessfulRequestCacher(clientCache, region);
        ArrayList<RequestHandler2> handlers = new ArrayList<>();
        if (builder.getRequestHandlers() != null) {
          handlers.addAll(builder.getRequestHandlers());
        }
        handlers.add(cacher);

        kms =
            cloneClientBuilder(builder)
                .withRegion(region)
                .withRequestHandlers(handlers.toArray(new RequestHandler2[handlers.size()]))
                .build();
        cacher.client_ = kms;

        return kms;
      };
    }

    protected void snoopClientCache(ConcurrentHashMap<String, AWSKMS> map) {
      // no-op - this is a test hook
    }
  }

  private static class SuccessfulRequestCacher extends RequestHandler2 {
    private final ConcurrentHashMap<String, AWSKMS> cache_;
    private final String region_;
    private AWSKMS client_;

    volatile boolean ranBefore_ = false;

    private SuccessfulRequestCacher(
        final ConcurrentHashMap<String, AWSKMS> cache, final String region) {
      this.region_ = region;
      this.cache_ = cache;
    }

    @Override
    public void afterResponse(final Request<?> request, final Response<?> response) {
      if (ranBefore_) return;
      ranBefore_ = true;

      cache_.putIfAbsent(region_, client_);
    }

    @Override
    public void afterError(
        final Request<?> request, final Response<?> response, final Exception e) {
      if (ranBefore_) return;
      if (e instanceof AmazonServiceException) {
        ranBefore_ = true;
        cache_.putIfAbsent(region_, client_);
      }
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  private KmsMasterKeyProvider(
      RegionalClientSupplier supplier,
      String defaultRegion,
      List<String> keyIds,
      List<String> grantTokens,
      boolean onlyOneRegion,
      boolean isDiscovery,
      DiscoveryFilter discoveryFilter) {
    if (!isDiscovery && (keyIds == null || keyIds.isEmpty())) {
      throw new IllegalArgumentException(
          "Strict mode must be configured with a non-empty " + "list of keyIds.");
    }

    if (!isDiscovery && discoveryFilter != null) {
      throw new IllegalArgumentException(
          "Strict mode cannot be configured with a " + "discovery filter.");
    }

    if (onlyOneRegion) {
      // restrict this provider to only the default region to avoid code using the legacy ctors from
      // unexpectedly
      // starting to make cross-region calls
      RegionalClientSupplier originalSupplier = supplier;

      supplier =
          region -> {
            if (!Objects.equals(region, defaultRegion)) {
              // An appropriate exception will be thrown elsewhere if return null
              return null;
            }

            return originalSupplier.getClient(region);
          };
    }

    this.regionalClientSupplier_ = supplier;
    this.defaultRegion_ = defaultRegion;
    this.keyIds_ = Collections.unmodifiableList(new ArrayList<>(keyIds));

    this.isDiscovery_ = isDiscovery;
    this.discoveryFilter_ = discoveryFilter;
    this.grantTokens_ = grantTokens;
  }

  // Helper ctor for legacy ctors
  private KmsMasterKeyProvider(
      RegionalClientSupplier supplier, String defaultRegion, List<String> keyIds) {
    this(supplier, defaultRegion, keyIds, new ArrayList<>(), true, IS_DISCOVERY_DEFAULT, null);
  }

  private static RegionalClientSupplier defaultProvider() {
    return builder().clientFactory();
  }

  /**
   * Returns an instance of this object with default settings, default credentials, and configured
   * to talk to the {@link Regions#DEFAULT_REGION}.
   *
   * @deprecated The default region set by this constructor is subject to change. Use the builder
   *     method to construct instances of this class for better control.
   */
  @Deprecated
  public KmsMasterKeyProvider() {
    this(defaultProvider(), Regions.DEFAULT_REGION.getName(), emptyList());
  }

  /**
   * Returns an instance of this object with default settings and credentials configured to speak to
   * the region specified by {@code keyId} (if specified). Data will be protected with {@code keyId}
   * as appropriate.
   *
   * <p>The default region will be set to that of the given key ID, or to the AWS SDK default region
   * if a bare key ID or alias is passed.
   *
   * @deprecated The default region set by this constructor is subject to change. Use the builder
   *     method to construct instances of this class for better control.
   */
  @Deprecated
  public KmsMasterKeyProvider(final String keyId) {
    this(defaultProvider(), getStartingRegion(keyId).getName(), singletonList(keyId));
  }

  /**
   * Returns an instance of this object with default settings configured to speak to the region
   * specified by {@code keyId} (if specified). Data will be protected with {@code keyId} as
   * appropriate.
   *
   * @deprecated The default region set by this constructor is subject to change. Use the builder
   *     method to construct instances of this class for better control.
   */
  @Deprecated
  public KmsMasterKeyProvider(final AWSCredentials creds, final String keyId) {
    this(
        new AWSStaticCredentialsProvider(creds),
        getStartingRegion(keyId),
        new ClientConfiguration(),
        keyId);
  }

  /**
   * Returns an instance of this object with default settings configured to speak to the region
   * specified by {@code keyId} (if specified). Data will be protected with {@code keyId} as
   * appropriate.
   *
   * <p>The default region will be set to that of the given key ID, or to the AWS SDK default region
   * if a bare key ID or alias is passed.
   *
   * @deprecated The default region set by this constructor is subject to change. Use the builder
   *     method to construct instances of this class for better control.
   */
  @Deprecated
  public KmsMasterKeyProvider(final AWSCredentialsProvider creds, final String keyId) {
    this(creds, getStartingRegion(keyId), new ClientConfiguration(), keyId);
  }

  /**
   * Returns an instance of this object with default settings and configured to talk to the {@link
   * Regions#DEFAULT_REGION}.
   *
   * @deprecated The default region set by this constructor is subject to change. Use the builder
   *     method to construct instances of this class for better control.
   */
  @Deprecated
  public KmsMasterKeyProvider(final AWSCredentials creds) {
    this(
        new AWSStaticCredentialsProvider(creds),
        Region.getRegion(Regions.DEFAULT_REGION),
        new ClientConfiguration(),
        Collections.<String>emptyList());
  }

  /**
   * Returns an instance of this object with default settings and configured to talk to the {@link
   * Regions#DEFAULT_REGION}.
   *
   * @deprecated The default region set by this constructor is subject to change. Use the builder
   *     method to construct instances of this class for better control.
   */
  @Deprecated
  public KmsMasterKeyProvider(final AWSCredentialsProvider creds) {
    this(
        creds,
        Region.getRegion(Regions.DEFAULT_REGION),
        new ClientConfiguration(),
        Collections.<String>emptyList());
  }

  /**
   * Returns an instance of this object with the supplied configuration and credentials. {@code
   * keyId} will be used to protect data.
   *
   * @deprecated This constructor implicitly configures the KMS Master Key Provider to perform
   *     discovery behavior on decrypt, which is a behavior that should be constructed explicitly.
   *     To create a KMS Master Key Provider that continues to perform discovery on decrypt, use
   *     {@link KmsMasterKeyProvider.Builder#buildDiscovery()} or {@link
   *     KmsMasterKeyProvider.Builder#buildDiscovery(DiscoveryFilter)}. To create a KMS Master Key
   *     Provider that restricts what keys to attempt decryption with to a set of configured keys,
   *     use {@link KmsMasterKeyProvider.Builder#buildStrict(List)}.
   */
  @Deprecated
  public KmsMasterKeyProvider(
      final AWSCredentialsProvider creds,
      final Region region,
      final ClientConfiguration clientConfiguration,
      final String keyId) {
    this(creds, region, clientConfiguration, singletonList(keyId));
  }

  /**
   * Returns an instance of this object with the supplied configuration and credentials. all keys
   * listed in {@code keyIds} will be used to protect data.
   *
   * @deprecated This constructor implicitly configures the KMS Master Key Provider to perform
   *     discovery behavior on decrypt, which is a behavior that should be constructed explicitly.
   *     To create a KMS Master Key Provider that continues to perform discovery on decrypt, use
   *     {@link KmsMasterKeyProvider.Builder#buildDiscovery()} or {@link
   *     KmsMasterKeyProvider.Builder#buildDiscovery(DiscoveryFilter)}. To create a KMS Master Key
   *     Provider that restricts what keys to attempt decryption with to a set of configured keys,
   *     use {@link KmsMasterKeyProvider.Builder#buildStrict(List)}.
   */
  @Deprecated
  public KmsMasterKeyProvider(
      final AWSCredentialsProvider creds,
      final Region region,
      final ClientConfiguration clientConfiguration,
      final List<String> keyIds) {
    this(
        builder()
            .withClientBuilder(
                AWSKMSClientBuilder.standard()
                    .withClientConfiguration(clientConfiguration)
                    .withCredentials(creds))
            .clientFactory(),
        region.getName(),
        keyIds);
  }

  /**
   * Returns an instance of this object with the supplied client and region; the client will be
   * configured to use the provided region. All keys listed in {@code keyIds} will be used to
   * protect data.
   *
   * @deprecated This constructor modifies the passed-in KMS client by setting its region. This
   *     functionality may be removed in future releases. Use the builder to construct instances of
   *     this class instead.
   */
  @Deprecated
  public KmsMasterKeyProvider(final AWSKMS kms, final Region region, final List<String> keyIds) {
    this(requestedRegion -> kms, region.getName(), keyIds);

    kms.setRegion(region);
  }

  /** Returns "aws-kms" */
  @Override
  public String getDefaultProviderId() {
    return PROVIDER_NAME;
  }

  @Override
  public KmsMasterKey getMasterKey(final String provider, final String keyId)
      throws UnsupportedProviderException, NoSuchMasterKeyException {
    if (!canProvide(provider)) {
      throw new UnsupportedProviderException();
    }

    if (!isDiscovery_ && !keyIds_.contains(keyId)) {
      throw new NoSuchMasterKeyException("Key must be in supplied list of keyIds.");
    }

    final AwsKmsCmkArnInfo arnInfo = parseInfoFromKeyArn(keyId);

    if (isDiscovery_ && discoveryFilter_ != null && (arnInfo == null)) {
      throw new NoSuchMasterKeyException(
          "Cannot use non-ARN key identifiers or aliases if " + "discovery filter is configured.");
    } else if (isDiscovery_
        && discoveryFilter_ != null
        && !discoveryFilter_.allowsPartitionAndAccount(
            arnInfo.getPartition(), arnInfo.getAccountId())) {
      throw new NoSuchMasterKeyException(
          "Cannot use key in partition "
              + arnInfo.getPartition()
              + " with account id "
              + arnInfo.getAccountId()
              + " with configured discovery filter.");
    }

    String regionName = defaultRegion_;
    if (arnInfo != null) {
      regionName = arnInfo.getRegion();
    }

    String regionName_ = regionName;

    Supplier<AWSKMS> kmsSupplier =
        () -> {
          AWSKMS kms = regionalClientSupplier_.getClient(regionName_);
          if (kms == null) {
            throw new AwsCryptoException("Can't use keys from region " + regionName_);
          }
          return kms;
        };

    final KmsMasterKey result = KmsMasterKey.getInstance(kmsSupplier, keyId, this);
    result.setGrantTokens(grantTokens_);
    return result;
  }

  /** Returns all CMKs provided to the constructor of this object. */
  @Override
  public List<KmsMasterKey> getMasterKeysForEncryption(final MasterKeyRequest request) {
    if (keyIds_ == null) {
      return emptyList();
    }
    List<KmsMasterKey> result = new ArrayList<>(keyIds_.size());
    for (String id : keyIds_) {
      result.add(getMasterKey(id));
    }
    return result;
  }

  @Override
  public DataKey<KmsMasterKey> decryptDataKey(
      final CryptoAlgorithm algorithm,
      final Collection<? extends EncryptedDataKey> encryptedDataKeys,
      final Map<String, String> encryptionContext)
      throws AwsCryptoException {
    final List<Exception> exceptions = new ArrayList<>();
    for (final EncryptedDataKey edk : encryptedDataKeys) {
      if (canProvide(edk.getProviderId())) {
        try {
          final String keyArn = new String(edk.getProviderInformation(), StandardCharsets.UTF_8);
          // This will throw if we can't use this key for whatever reason
          return getMasterKey(keyArn)
              .decryptDataKey(algorithm, singletonList(edk), encryptionContext);
        } catch (final Exception asex) {
          exceptions.add(asex);
        }
      }
    }
    throw buildCannotDecryptDksException(exceptions);
  }

  /**
   * @deprecated This method is inherently not thread safe. Use {@link
   *     KmsMasterKey#setGrantTokens(List)} instead. {@link KmsMasterKeyProvider}s constructed using
   *     the builder will throw an exception on attempts to modify the list of grant tokens.
   */
  @Deprecated
  @Override
  public void setGrantTokens(final List<String> grantTokens) {
    try {
      this.grantTokens_.clear();
      this.grantTokens_.addAll(grantTokens);
    } catch (UnsupportedOperationException e) {
      throw grantTokenError();
    }
  }

  @Override
  public List<String> getGrantTokens() {
    return new ArrayList<>(grantTokens_);
  }

  /**
   * @deprecated This method is inherently not thread safe. Use {@link #withGrantTokens(List)} or
   *     {@link KmsMasterKey#setGrantTokens(List)} instead. {@link KmsMasterKeyProvider}s
   *     constructed using the builder will throw an exception on attempts to modify the list of
   *     grant tokens.
   */
  @Deprecated
  @Override
  public void addGrantToken(final String grantToken) {
    try {
      grantTokens_.add(grantToken);
    } catch (UnsupportedOperationException e) {
      throw grantTokenError();
    }
  }

  private RuntimeException grantTokenError() {
    return new IllegalStateException(
        "This master key provider is immutable. Use withGrantTokens instead.");
  }

  /**
   * Returns a new {@link KmsMasterKeyProvider} that is configured identically to this one, except
   * with the given list of grant tokens. The grant token list in the returned provider is immutable
   * (but can be further overridden by invoking withGrantTokens again).
   *
   * @param grantTokens
   * @return
   */
  public KmsMasterKeyProvider withGrantTokens(List<String> grantTokens) {
    grantTokens = Collections.unmodifiableList(new ArrayList<>(grantTokens));

    return new KmsMasterKeyProvider(
        regionalClientSupplier_,
        defaultRegion_,
        keyIds_,
        grantTokens,
        false,
        isDiscovery_,
        discoveryFilter_);
  }

  /**
   * Returns a new {@link KmsMasterKeyProvider} that is configured identically to this one, except
   * with the given list of grant tokens. The grant token list in the returned provider is immutable
   * (but can be further overridden by invoking withGrantTokens again).
   *
   * @param grantTokens
   * @return
   */
  public KmsMasterKeyProvider withGrantTokens(String... grantTokens) {
    return withGrantTokens(asList(grantTokens));
  }

  private static Region getStartingRegion(final String keyArn) {
    final AwsKmsCmkArnInfo arnInfo = parseInfoFromKeyArn(keyArn);
    if (arnInfo != null) {
      return RegionUtils.getRegion(arnInfo.getRegion());
    }
    final Region currentRegion = Regions.getCurrentRegion();
    if (currentRegion != null) {
      return currentRegion;
    }

    return Region.getRegion(Regions.DEFAULT_REGION);
  }

  private static AwsKmsCmkArnInfo parseInfoFromKeyArn(final String keyArn) {
    final String[] parts = keyArn.split(":", 6);
    if (!parts[0].equals("arn") || parts.length < 6) {
      return null;
    }
    if (!parts[2].equals("kms")) {
      return null;
    }
    if (parts[1].isEmpty() || parts[3].isEmpty() || parts[4].isEmpty()) {
      return null;
    }

    return new AwsKmsCmkArnInfo(parts[1], parts[3], parts[4]);
  }
}
