// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import static com.amazonaws.encryptionsdk.internal.AwsKmsCmkArnInfo.*;
import static com.amazonaws.encryptionsdk.internal.AwsKmsCmkArnInfo.parseInfoFromKeyArn;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.internal.AwsKmsCmkArnInfo;
import com.amazonaws.handlers.RequestHandler2;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

// = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.5
// # MUST implement the Master Key Provider Interface (../master-key-
// # provider-interface.md#interface)
/**
 * Represents a list Aws KMS keys and is used to encrypt/decrypt data with {@link AwsCrypto}. Some
 * of these keys may be multi region keys, in which case this component is able to recognize
 * different regional replicas of this multi region key as the same.
 */
public final class AwsKmsMrkAwareMasterKeyProvider
    extends MasterKeyProvider<AwsKmsMrkAwareMasterKey> {
  private static final String PROVIDER_NAME = "aws-kms";
  private final List<String> keyIds_;
  private final List<String> grantTokens_;

  private final boolean isDiscovery_;
  private final DiscoveryFilter discoveryFilter_;
  private final String discoveryMrkRegion_;

  private final KmsMasterKeyProvider.RegionalClientSupplier regionalClientSupplier_;
  private final String defaultRegion_;

  public static class Builder implements Cloneable {
    private String defaultRegion_ = null;
    private Optional<KmsMasterKeyProvider.RegionalClientSupplier> regionalClientSupplier_ =
        Optional.empty();
    private AWSKMSClientBuilder templateBuilder_ = null;
    private DiscoveryFilter discoveryFilter_ = null;
    private String discoveryMrkRegion_ = null;

    Builder() {
      // Default access: Don't allow outside classes to extend this class
    }

    public Builder clone() {
      try {
        AwsKmsMrkAwareMasterKeyProvider.Builder cloned =
            (AwsKmsMrkAwareMasterKeyProvider.Builder) super.clone();

        if (templateBuilder_ != null) {
          cloned.templateBuilder_ = cloneClientBuilder(templateBuilder_);
        }

        return cloned;
      } catch (CloneNotSupportedException e) {
        throw new Error("Impossible: CloneNotSupportedException", e);
      }
    }

    /**
     * Sets the default region. This region will be used when specifying key IDs for encryption or
     * in {@link AwsKmsMrkAwareMasterKeyProvider#getMasterKey(String)} that are not full ARNs, but
     * are instead bare key IDs or aliases.
     *
     * <p>If the default region is not specified, the AWS SDK default region will be used.
     *
     * @see KmsMasterKeyProvider.Builder#withDefaultRegion(String)
     * @param defaultRegion The default region to use.
     */
    public AwsKmsMrkAwareMasterKeyProvider.Builder withDefaultRegion(String defaultRegion) {
      this.defaultRegion_ = defaultRegion;
      return this;
    }

    /**
     * Sets the region contacted for multi-region keys when in Discovery mode. This region will be
     * used when a multi-region key is discovered on decrypt by {@link
     * AwsKmsMrkAwareMasterKeyProvider#getMasterKey(String)}.
     *
     * <p>
     *
     * @param discoveryMrkRegion The region to contact to attempt to decrypt multi-region keys.
     */
    public AwsKmsMrkAwareMasterKeyProvider.Builder withDiscoveryMrkRegion(
        String discoveryMrkRegion) {
      this.discoveryMrkRegion_ = discoveryMrkRegion;
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
     * @see
     *     KmsMasterKeyProvider.Builder#withCustomClientFactory(KmsMasterKeyProvider.RegionalClientSupplier)
     */
    public AwsKmsMrkAwareMasterKeyProvider.Builder withCustomClientFactory(
        KmsMasterKeyProvider.RegionalClientSupplier regionalClientSupplier) {
      if (templateBuilder_ != null) {
        throw clientSupplierComboException();
      }

      regionalClientSupplier_ = Optional.of(regionalClientSupplier);
      return this;
    }

    private RuntimeException clientSupplierComboException() {
      return new IllegalStateException(
          "withCustomClientFactory cannot be used in conjunction with "
              + "withCredentials or withClientBuilder");
    }

    /**
     * Configures the {@link AwsKmsMrkAwareMasterKeyProvider} to use specific credentials. If a
     * builder was previously set, this will override whatever credentials it set.
     *
     * @see KmsMasterKeyProvider.Builder#withCredentials(AWSCredentialsProvider)
     */
    public AwsKmsMrkAwareMasterKeyProvider.Builder withCredentials(
        AWSCredentialsProvider credentialsProvider) {
      if (regionalClientSupplier_.isPresent()) {
        throw clientSupplierComboException();
      }

      if (templateBuilder_ == null) {
        templateBuilder_ = AWSKMSClientBuilder.standard();
      }

      templateBuilder_.setCredentials(credentialsProvider);

      return this;
    }

    /**
     * Configures the {@link AwsKmsMrkAwareMasterKeyProvider} to use specific credentials. If a
     * builder was previously set, this will override whatever credentials it set.
     *
     * @see KmsMasterKeyProvider.Builder#withCredentials(AWSCredentials)
     */
    public AwsKmsMrkAwareMasterKeyProvider.Builder withCredentials(AWSCredentials credentials) {
      return withCredentials(new AWSStaticCredentialsProvider(credentials));
    }

    /**
     * Configures the {@link AwsKmsMrkAwareMasterKeyProvider} to use settings from this {@link
     * AWSKMSClientBuilder} to configure KMS clients. Note that the region set on this builder will
     * be ignored, but all other settings will be propagated into the regional clients.
     *
     * <p>This method will overwrite any credentials set using {@link
     * #withCredentials(AWSCredentialsProvider)}.
     *
     * @see KmsMasterKeyProvider.Builder#withClientBuilder(AWSKMSClientBuilder)
     */
    public AwsKmsMrkAwareMasterKeyProvider.Builder withClientBuilder(AWSKMSClientBuilder builder) {
      if (regionalClientSupplier_.isPresent()) {
        throw clientSupplierComboException();
      }
      final AWSKMSClientBuilder newBuilder = cloneClientBuilder(builder);
      this.templateBuilder_ = newBuilder;

      return this;
    }

    /**
     * Builds the master key provider in Discovery Mode. In Discovery Mode the KMS Master Key
     * Provider will attempt to decrypt using any key identifier it discovers in the encrypted
     * message. KMS Master Key Providers in Discovery Mode will not encrypt data keys.
     *
     * @see KmsMasterKeyProvider.Builder#buildDiscovery()
     */
    public AwsKmsMrkAwareMasterKeyProvider buildDiscovery() {
      final boolean isDiscovery = true;
      if (discoveryMrkRegion_ == null) {
        // The AWS SDK has a default process for evaluating the default Region. This returns null if
        // no
        // default region is found. Because a default region _may_ not be needed.
        // Note: Final Null check is at
        // com.amazonaws.encryptionsdk.kms.AwsKmsMrkAwareMasterKeyProvider#AwsKmsMrkAwareMasterKeyProvider#L417
        try {
          // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
          // # In
          // # discovery mode if a default MRK Region is not configured the AWS SDK
          // # Default Region MUST be used.
          discoveryMrkRegion_ =
              new com.amazonaws.regions.DefaultAwsRegionProviderChain().getRegion();
        } catch (SdkClientException ex) {
          throw new AwsCryptoException(
              "DiscoveryMrkRegion was not set and Default AWS Region Provider Chain could not load one.",
              ex);
        }
      }

      return new AwsKmsMrkAwareMasterKeyProvider(
          // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
          // # The regional client
          // # supplier MUST be defined in discovery mode.
          regionalClientSupplier_.orElse(
              clientFactory(new ConcurrentHashMap<>(), templateBuilder_)),
          defaultRegion_,
          // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
          // # The key id list MUST be empty in discovery mode.
          emptyList(),
          emptyList(),
          isDiscovery,
          discoveryFilter_,
          // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
          // # In
          // # discovery mode if a default MRK Region is not configured the AWS SDK
          // # Default Region MUST be used.
          discoveryMrkRegion_);
    }

    /**
     * Builds the master key provider in Discovery Mode with a {@link DiscoveryFilter}. In Discovery
     * Mode the KMS Master Key Provider will attempt to decrypt using any key identifier it
     * discovers in the encrypted message that is accepted by the {@code filter}. KMS Master Key
     * Providers in Discovery Mode will not encrypt data keys.
     *
     * @see KmsMasterKeyProvider.Builder#buildDiscovery(DiscoveryFilter)
     */
    public AwsKmsMrkAwareMasterKeyProvider buildDiscovery(DiscoveryFilter filter) {
      discoveryFilter_ = filter;
      return buildDiscovery();
    }

    /**
     * Builds the master key provider in Strict Mode. KMS Master Key Providers in Strict Mode will
     * only attempt to decrypt using key ARNs listed in {@code keyIds}. KMS Master Key Providers in
     * Strict Mode will encrypt data keys using the keys listed in {@code keyIds}
     *
     * <p>In Strict Mode, one or more CMKs must be provided. For Master Key Providers that will only
     * be used for encryption, you can use any valid KMS key identifier. For providers that will be
     * used for decryption, you must use the key ARN; key ids, alias names, and alias ARNs are not
     * supported.
     *
     * @see KmsMasterKeyProvider.Builder#buildStrict(List)
     */
    public AwsKmsMrkAwareMasterKeyProvider buildStrict(List<String> keyIds) {
      final boolean isDiscovery = false;

      return new AwsKmsMrkAwareMasterKeyProvider(
          regionalClientSupplier_.orElse(
              clientFactory(new ConcurrentHashMap<>(), templateBuilder_)),
          defaultRegion_,
          new ArrayList<String>(keyIds),
          emptyList(),
          isDiscovery,
          // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
          // # A discovery filter MUST NOT be configured in strict mode.
          null,
          // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
          // # A default MRK Region MUST NOT be configured in strict mode.
          null);
    }

    /**
     * Builds the master key provider in strict mode. KMS Master Key Providers in Strict Mode will
     * only attempt to decrypt using key ARNs listed in {@code keyIds}. KMS Master Key Providers in
     * Strict Mode will encrypt data keys using the keys listed in {@code keyIds}
     *
     * <p>In Strict Mode, one or more CMKs must be provided. For Master Key Providers that will only
     * be used for encryption, you can use any valid KMS key identifier. For providers that will be
     * used for decryption, you must use the key ARN; key ids, alias names, and alias ARNs are not
     * supported.
     *
     * @see KmsMasterKeyProvider.Builder#buildStrict(String...)
     */
    public AwsKmsMrkAwareMasterKeyProvider buildStrict(String... keyIds) {
      return buildStrict(asList(keyIds));
    }

    static KmsMasterKeyProvider.RegionalClientSupplier clientFactory(
        ConcurrentHashMap<String, AWSKMS> clientCache, AWSKMSClientBuilder templateBuilder) {

      // Clone again; this MKP builder might be reused to build a second MKP with different creds.
      AWSKMSClientBuilder builder =
          templateBuilder != null
              ? cloneClientBuilder(templateBuilder)
              : AWSKMSClientBuilder.standard();

      return region -> {
        if (clientCache.containsKey(region)) {
          return clientCache.get(region);
        }

        // We can't just use computeIfAbsent as we need to avoid leaking KMS clients if we're asked
        // to decrypt
        // an EDK with a bogus region in its ARN. So we'll install a request handler to identify the
        // first
        // successful call, and cache it when we see that.
        final KmsMasterKeyProvider.SuccessfulRequestCacher cacher =
            new KmsMasterKeyProvider.SuccessfulRequestCacher(clientCache, region);
        final ArrayList<RequestHandler2> handlers = new ArrayList<>();
        if (builder.getRequestHandlers() != null) {
          handlers.addAll(builder.getRequestHandlers());
        }
        handlers.add(cacher);

        final AWSKMS kms =
            cloneClientBuilder(builder)
                .withRegion(region)
                .withRequestHandlers(handlers.toArray(new RequestHandler2[handlers.size()]))
                .build();
        return cacher.setClient(kms);
      };
    }

    static AWSKMSClientBuilder cloneClientBuilder(final AWSKMSClientBuilder builder) {
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
     * The AWS SDK has a default process for evaluating the default Region. This returns null if no
     * default region is found. Because a default region _may_ not be needed.
     */
    private static String getSdkDefaultRegion() {
      try {
        return new com.amazonaws.regions.DefaultAwsRegionProviderChain().getRegion();
      } catch (SdkClientException ex) {
        return null;
      }
    }
  }

  public static AwsKmsMrkAwareMasterKeyProvider.Builder builder() {
    return new AwsKmsMrkAwareMasterKeyProvider.Builder();
  }

  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
  // # On initialization the caller MUST provide:
  private AwsKmsMrkAwareMasterKeyProvider(
      KmsMasterKeyProvider.RegionalClientSupplier supplier,
      String defaultRegion,
      List<String> keyIds,
      List<String> grantTokens,
      boolean isDiscovery,
      DiscoveryFilter discoveryFilter,
      String discoveryMrkRegion) {
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
    // # The key id list MUST NOT be empty or null in strict mode.
    if (!isDiscovery && (keyIds == null || keyIds.isEmpty())) {
      throw new IllegalArgumentException(
          "Strict mode must be configured with a non-empty " + "list of keyIds.");
    }
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
    // # The key id
    // # list MUST NOT contain any null or empty string values.
    if (!isDiscovery && (keyIds.contains(null) || keyIds.contains(""))) {
      throw new IllegalArgumentException(
          "Strict mode cannot be configured with a " + "null key identifier.");
    }

    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
    // # All AWS KMS
    // # key identifiers are be passed to Assert AWS KMS MRK are unique (aws-
    // # kms-mrk-are-unique.md#Implementation) and the function MUST return
    // # success.
    assertMrksAreUnique(keyIds);
    if (!isDiscovery
        && defaultRegion == null
        && keyIds.stream()
            .map(identifier -> parseInfoFromKeyArn(identifier))
            .anyMatch(info -> info == null)) {
      throw new AwsCryptoException(
          "Can't use non-ARN key identifiers or aliases when " + "no default region is set");
    }
    /* Precondition (untested): Discovery filter is only valid in discovery mode. */
    if (!isDiscovery && discoveryFilter != null) {
      throw new IllegalArgumentException(
          "Strict mode cannot be configured with a " + "discovery filter.");
    }
    /* Precondition (untested): Discovery mode can not have any keys to filter. */
    if (isDiscovery && !keyIds.isEmpty()) {
      throw new IllegalArgumentException("Discovery mode can not be configured with keys.");
    }
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
    // # If an AWS SDK Default Region can not be
    // # obtained initialization MUST fail.
    if (isDiscovery && discoveryMrkRegion == null) {
      throw new IllegalArgumentException("Discovery MRK region can not be null.");
    }

    this.regionalClientSupplier_ = supplier;
    // Null Pointer Exception (NPE) would be thrown
    // via result of extractRegion passed to KMS Client request around line 583.
    // We could refactor extractRegion to handle Strict and Discovery separately,
    // which would allow us to avoid this potentially un-needed new
    // DefaultAwsRegionProviderChain().getRegion()
    // call.
    // Otherwise, we have to have the call.
    if (defaultRegion == null) {
      try {
        defaultRegion = new com.amazonaws.regions.DefaultAwsRegionProviderChain().getRegion();
        if (defaultRegion == null) {
          throw new AwsCryptoException(
              "Default Region was not set and Default AWS Region Provider Chain could not load one.");
        }
      } catch (SdkClientException ex) {
        throw new AwsCryptoException(
            "Default Region was not set and Default AWS Region Provider Chain could not load one.",
            ex);
      }
    }
    this.defaultRegion_ = defaultRegion;
    this.keyIds_ = Collections.unmodifiableList(new ArrayList<>(keyIds));

    this.isDiscovery_ = isDiscovery;
    this.discoveryFilter_ = discoveryFilter;
    this.discoveryMrkRegion_ = discoveryMrkRegion;
    this.grantTokens_ = grantTokens;
  }

  // = compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
  // # The caller MUST provide:
  /** Refactored into a pure function to facilitate testing and correctness. */
  static void assertMrksAreUnique(List<String> keyIdentifiers) {

    List<String> duplicateMultiRegionKeyIdentifiers =
        keyIdentifiers.stream()
            /* Collect a map of resource to identifier.
             * This lets me group duplicates by "resource".
             * This is because the identifier can be either an ARN or a raw identifier.
             * By having the both the key id and the identifier I can ensure the uniqueness of
             * the key id and the error message to the caller can contain both identifiers
             * to facilitate debugging.
             */
            .collect(
                Collectors.groupingBy(
                    AwsKmsMrkAwareMasterKeyProvider::getResourceForResourceTypeKey))
            .entrySet()
            .stream()
            // = compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
            // # If there are zero duplicate resource ids between the multi-region
            // # keys, this function MUST exit successfully
            .filter(maybeDuplicate -> maybeDuplicate.getValue().size() > 1)
            // = compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
            // # If the list does not contain any multi-Region keys (aws-kms-key-
            // # arn.md#identifying-an-aws-kms-multi-region-key) this function MUST
            // # exit successfully.
            //
            .filter(maybeMrk -> isMRK(maybeMrk.getKey()))
            /* Flatten the duplicate identifiers into a single list. */
            .flatMap(mrkEntry -> mrkEntry.getValue().stream())
            .collect(Collectors.toList());

    // = compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    // # If any duplicate multi-region resource ids exist, this function MUST
    // # yield an error that includes all identifiers with duplicate resource
    // # ids not only the first duplicate found.
    if (duplicateMultiRegionKeyIdentifiers.size() > 1) {
      throw new IllegalArgumentException(
          "Duplicate multi-region keys are not allowed:\n"
              + String.join(", ", duplicateMultiRegionKeyIdentifiers));
    }
  }

  /**
   * Helper method for
   *
   * @see AwsKmsMrkAwareMasterKeyProvider#assertMrksAreUnique(List)
   *     <p>Refoactored into a pure function to simplify testing and ensure correctness.
   */
  static String getResourceForResourceTypeKey(String identifier) {
    final AwsKmsCmkArnInfo info = parseInfoFromKeyArn(identifier);
    if (info == null) return identifier;

    if (!info.getResourceType().equals("key")) {
      return identifier;
    }

    return info.getResource();
  }

  /** Returns "aws-kms" */
  @Override
  public String getDefaultProviderId() {
    return PROVIDER_NAME;
  }

  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
  // # The input MUST be the same as the Master Key Provider Get Master Key
  // # (../master-key-provider-interface.md#get-master-key) interface.
  /**
   * Added flexibility in matching multi-Region keys from different regions.
   *
   * @see KmsMasterKey#getMasterKey(String, String)
   */
  @Override
  public AwsKmsMrkAwareMasterKey getMasterKey(final String providerId, final String requestedKeyArn)
      throws UnsupportedProviderException, NoSuchMasterKeyException {
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # The function MUST only provide master keys if the input provider id
    // # equals "aws-kms".
    if (!canProvide(providerId)) {
      throw new UnsupportedProviderException();
    }

    /* There SHOULD only be one match.
     * An unambiguous multi-region key for the family
     * of related multi-region keys is required.
     * See `assertMrksAreUnique`.
     * However, in the case of single region keys or aliases,
     * duplicates _are_ possible.
     */
    Optional<String> matchedArn =
        keyIds_.stream().filter(t -> awsKmsArnMatchForDecrypt(t, requestedKeyArn)).findFirst();
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # In strict mode, the requested AWS KMS key ARN MUST
    // # match a member of the configured key ids by using AWS KMS MRK Match
    // # for Decrypt (aws-kms-mrk-match-for-decrypt.md#implementation)
    // # otherwise this function MUST error.
    if (!isDiscovery_ && !matchedArn.isPresent()) {
      throw new NoSuchMasterKeyException("Key must be in supplied list of keyIds.");
    }

    final AwsKmsCmkArnInfo requestedKeyArnInfo = parseInfoFromKeyArn(requestedKeyArn);
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # In discovery mode, the requested
    // # AWS KMS key identifier MUST be a well formed AWS KMS ARN.
    if (isDiscovery_ && requestedKeyArnInfo == null) {
      throw new NoSuchMasterKeyException(
          "Cannot use AWS KMS identifiers " + "when in discovery mode.");
    }
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # In
    // # discovery mode if a discovery filter is configured the requested AWS
    // # KMS key ARN's "partition" MUST match the discovery filter's
    // # "partition" and the AWS KMS key ARN's "account" MUST exist in the
    // # discovery filter's account id set.
    if (isDiscovery_
        && discoveryFilter_ != null
        && !discoveryFilter_.allowsPartitionAndAccount(
            requestedKeyArnInfo.getPartition(), requestedKeyArnInfo.getAccountId())) {
      throw new NoSuchMasterKeyException(
          "Cannot use key in partition "
              + requestedKeyArnInfo.getPartition()
              + " with account id "
              + requestedKeyArnInfo.getAccountId()
              + " with configured discovery filter.");
    }

    final String regionName_ =
        extractRegion(
            defaultRegion_, discoveryMrkRegion_, matchedArn, requestedKeyArnInfo, isDiscovery_);

    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # An AWS KMS client
    // # MUST be obtained by calling the regional client supplier with this
    // # AWS Region.
    AWSKMS kms = regionalClientSupplier_.getClient(regionName_);

    String keyIdentifier =
        isDiscovery_
            // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
            // # In discovery mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
            // # master-key.md) MUST be returned configured with
            ? requestedKeyArnInfo.toString(regionName_)
            // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
            // # In strict mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
            // # master-key.md) MUST be returned configured with
            : matchedArn.get();

    final AwsKmsMrkAwareMasterKey result =
        AwsKmsMrkAwareMasterKey.getInstance(kms, keyIdentifier, this);
    result.setGrantTokens(grantTokens_);
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # The output MUST be the same as the Master Key Provider Get Master Key
    // # (../master-key-provider-interface.md#get-master-key) interface.
    return result;
  }

  /**
   * Select the correct region from multiple default configurations and potentially related
   * multi-Region keys from different regions.
   *
   * <p>Refactored into a pure function to facilitate testing and ensure correctness.
   */
  static String extractRegion(
      final String defaultRegion,
      final String discoveryMrkRegion,
      final Optional<String> matchedArn,
      final AwsKmsCmkArnInfo requestedKeyArnInfo,
      final boolean isDiscovery) {
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # If the requested AWS KMS key identifier is not a well formed ARN the
    // # AWS Region MUST be the configured default region this SHOULD be
    // # obtained from the AWS SDK.
    if (requestedKeyArnInfo == null) return defaultRegion;
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # Otherwise if the requested AWS KMS key
    // # identifier is identified as a multi-Region key (aws-kms-key-
    // # arn.md#identifying-an-aws-kms-multi-region-key), then AWS Region MUST
    // # be the region from the AWS KMS key ARN stored in the provider info
    // # from the encrypted data key.
    if (!isMRK(requestedKeyArnInfo.getResource())
        || !requestedKeyArnInfo.getResourceType().equals("key")) {
      return requestedKeyArnInfo.getRegion();
    }
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # Otherwise if the mode is discovery then
    // # the AWS Region MUST be the discovery MRK region.
    if (isDiscovery) return discoveryMrkRegion;
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # Finally if the
    // # provider info is identified as a multi-Region key (aws-kms-key-
    // # arn.md#identifying-an-aws-kms-multi-region-key) the AWS Region MUST
    // # be the region from the AWS KMS key in the configured key ids matched
    // # to the requested AWS KMS key by using AWS KMS MRK Match for Decrypt
    // # (aws-kms-mrk-match-for-decrypt.md#implementation).
    return parseInfoFromKeyArn(matchedArn.get()).getRegion();
  }

  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
  // # The input MUST be the same as the Master Key Provider Get Master Keys
  // # For Encryption (../master-key-provider-interface.md#get-master-keys-
  // # for-encryption) interface.
  /**
   * Returns all CMKs provided to the constructor of this object.
   *
   * @see KmsMasterKey#getMasterKeysForEncryption(MasterKeyRequest)
   */
  @Override
  public List<AwsKmsMrkAwareMasterKey> getMasterKeysForEncryption(final MasterKeyRequest request) {
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
    // # If the configured mode is discovery the function MUST return an empty
    // # list.
    if (isDiscovery_) {
      return emptyList();
    }
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
    // # If the configured mode is strict this function MUST return a
    // # list of master keys obtained by calling Get Master Key (aws-kms-mrk-
    // # aware-master-key-provider.md#get-master-key) for each AWS KMS key
    // # identifier in the configured key ids
    List<AwsKmsMrkAwareMasterKey> result = new ArrayList<>(keyIds_.size());
    for (String id : keyIds_) {
      result.add(getMasterKey(id));
    }
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
    // # The output MUST be the same as the Master Key Provider Get Master
    // # Keys For Encryption (../master-key-provider-interface.md#get-master-
    // # keys-for-encryption) interface.
    return result;
  }

  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
  // # The input MUST be the same as the Master Key Provider Decrypt Data
  // # Key (../master-key-provider-interface.md#decrypt-data-key) interface.
  /**
   * @see KmsMasterKey#decryptDataKey(CryptoAlgorithm, Collection, Map)
   * @throws AwsCryptoException
   */
  @Override
  public DataKey<AwsKmsMrkAwareMasterKey> decryptDataKey(
      final CryptoAlgorithm algorithm,
      final Collection<? extends EncryptedDataKey> encryptedDataKeys,
      final Map<String, String> encryptionContext)
      throws AwsCryptoException {
    final List<Exception> exceptions = new ArrayList<>();

    return encryptedDataKeys.stream()
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
        // # The set of encrypted data keys MUST first be filtered to match this
        // # master key's configuration.
        .filter(
            edk -> {
              // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
              // # To match the encrypted data key's
              // # provider ID MUST exactly match the value "aws-kms".
              if (!canProvide(edk.getProviderId())) return false;

              final String providerInfo =
                  new String(edk.getProviderInformation(), StandardCharsets.UTF_8);
              final AwsKmsCmkArnInfo providerArnInfo = parseInfoFromKeyArn(providerInfo);

              // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
              // # Additionally
              // # each provider info MUST be a valid AWS KMS ARN (aws-kms-key-arn.md#a-
              // # valid-aws-kms-arn) with a resource type of "key".
              if (providerArnInfo == null || !"key".equals(providerArnInfo.getResourceType())) {
                throw new IllegalStateException("Invalid provider info in message.");
              }
              return true;
            })
        .map(
            edk -> {
              try {
                final String keyArn =
                    new String(edk.getProviderInformation(), StandardCharsets.UTF_8);

                // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
                // # For each encrypted data key in the filtered set, one at a time, the
                // # master key provider MUST call Get Master Key (aws-kms-mrk-aware-
                // # master-key-provider.md#get-master-key) with the encrypted data key's
                // # provider info as the AWS KMS key ARN.
                // This will throw if we can't use this key for whatever reason
                return getMasterKey(edk.getProviderId(), keyArn)
                    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
                    // # It MUST call Decrypt Data Key
                    // # (aws-kms-mrk-aware-master-key.md#decrypt-data-key) on this master key
                    // # with the input algorithm, this single encrypted data key, and the
                    // # input encryption context.
                    .decryptDataKey(algorithm, singletonList(edk), encryptionContext);
              } catch (final Exception ex) {
                // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
                // # If this attempt results in an error, then
                // # these errors MUST be collected.
                exceptions.add(ex);
                return null;
              }
            })
        /* Need to filter null because an Optional of a null is crazy.
         * `findFirst` will throw if it sees `null`.
         */
        .filter(Objects::nonNull)
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
        // # If the decrypt data key call is
        // # successful, then this function MUST return this result and not
        // # attempt to decrypt any more encrypted data keys.
        .findFirst()
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
        // # If all the input encrypted data keys have been processed then this
        // # function MUST yield an error that includes all the collected errors.
        //
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
        // # The output MUST be the same as the Master Key Provider Decrypt Data
        // # Key (../master-key-provider-interface.md#decrypt-data-key) interface.
        .orElseThrow(() -> buildCannotDecryptDksException(exceptions));
  }

  public List<String> getGrantTokens() {
    return new ArrayList<>(grantTokens_);
  }

  /**
   * Returns a new {@link AwsKmsMrkAwareMasterKeyProvider} that is configured identically to this
   * one, except with the given list of grant tokens. The grant token list in the returned provider
   * is immutable (but can be further overridden by invoking withGrantTokens again).
   */
  public AwsKmsMrkAwareMasterKeyProvider withGrantTokens(List<String> grantTokens) {
    grantTokens = Collections.unmodifiableList(new ArrayList<>(grantTokens));

    return new AwsKmsMrkAwareMasterKeyProvider(
        regionalClientSupplier_,
        defaultRegion_,
        keyIds_,
        grantTokens,
        isDiscovery_,
        discoveryFilter_,
        discoveryMrkRegion_);
  }

  /**
   * Returns a new {@link AwsKmsMrkAwareMasterKeyProvider} that is configured identically to this
   * one, except with the given list of grant tokens. The grant token list in the returned provider
   * is immutable (but can be further overridden by invoking withGrantTokens again).
   */
  public AwsKmsMrkAwareMasterKeyProvider withGrantTokens(String... grantTokens) {
    return withGrantTokens(asList(grantTokens));
  }
}
