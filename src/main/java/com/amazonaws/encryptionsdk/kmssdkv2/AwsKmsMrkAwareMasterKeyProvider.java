// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kmssdkv2;

import static com.amazonaws.encryptionsdk.internal.AwsKmsCmkArnInfo.*;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.internal.AwsKmsCmkArnInfo;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilter;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

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
  private final Region discoveryMrkRegion_;

  private final RegionalClientSupplier regionalClientSupplier_;
  private final Region defaultRegion_;

  public static class Builder implements Cloneable {
    private Region defaultRegion_ = getSdkDefaultRegion();

    private Supplier<KmsClientBuilder> builderSupplier_ = null;
    private RegionalClientSupplier regionalClientSupplier_ = null;

    private DiscoveryFilter discoveryFilter_ = null;
    private Region discoveryMrkRegion_ = this.defaultRegion_;

    Builder() {
      // Default access: Don't allow outside classes to extend this class
    }

    public Builder clone() {
      try {
        Builder cloned = (Builder) super.clone();

        cloned.builderSupplier_ = builderSupplier_;

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
     * @see KmsMasterKeyProvider.Builder#defaultRegion(Region)
     * @param defaultRegion The default region to use.
     */
    public Builder defaultRegion(Region defaultRegion) {
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
    public Builder discoveryMrkRegion(Region discoveryMrkRegion) {
      this.discoveryMrkRegion_ = discoveryMrkRegion;
      return this;
    }

    /**
     * Provides a custom factory function that will vend KMS clients. This is provided for advanced
     * use cases which require complete control over the client construction process.
     *
     * <p>Because the regional client supplier fully controls the client construction process, it is
     * not possible to configure the client through methods such as {@link
     * #builderSupplier(Supplier)}; if you try to use these in combination, an {@link
     * IllegalStateException} will be thrown.
     *
     * @see KmsMasterKeyProvider.Builder#customRegionalClientSupplier(RegionalClientSupplier)
     */
    public Builder customRegionalClientSupplier(RegionalClientSupplier regionalClientSupplier) {
      if (builderSupplier_ != null) {
        throw clientSupplierComboException();
      }

      regionalClientSupplier_ = regionalClientSupplier;
      return this;
    }

    /**
     * Configures the {@link AwsKmsMrkAwareMasterKeyProvider} to use settings from this {@link
     * KmsClientBuilder} to configure KMS clients. Note that the region set on this builder will be
     * ignored, but all other settings will be propagated into the regional clients.
     *
     * @see KmsMasterKeyProvider.Builder#builderSupplier(Supplier)
     */
    public Builder builderSupplier(Supplier<KmsClientBuilder> supplier) {
      if (regionalClientSupplier_ != null) {
        throw clientSupplierComboException();
      }

      this.builderSupplier_ = supplier;
      return this;
    }

    private RuntimeException clientSupplierComboException() {
      return new IllegalStateException(
          "only one of builderSupplier and customRegionalClientSupplier may be used");
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

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
      // # The regional client
      // # supplier MUST be defined in discovery mode.
      RegionalClientSupplier clientSupplier = regionalClientSupplier_;
      if (clientSupplier == null) {
        clientSupplier = clientFactory(new ConcurrentHashMap<>(), builderSupplier_);
      }

      return new AwsKmsMrkAwareMasterKeyProvider(
          clientSupplier,
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
          discoveryMrkRegion_ == null ? defaultRegion_ : discoveryMrkRegion_);
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

      RegionalClientSupplier clientSupplier = regionalClientSupplier_;
      if (clientSupplier == null) {
        clientSupplier = clientFactory(new ConcurrentHashMap<>(), builderSupplier_);
      }

      return new AwsKmsMrkAwareMasterKeyProvider(
          clientSupplier,
          defaultRegion_,
          new ArrayList<>(keyIds),
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

    static RegionalClientSupplier clientFactory(
        ConcurrentHashMap<Region, KmsClient> clientCache,
        Supplier<KmsClientBuilder> builderSupplier) {

      return region -> {
        /* Check for early return (Postcondition): If a client already exists, use that. */
        if (clientCache.containsKey(region)) {
          return clientCache.get(region);
        }

        KmsClientBuilder builder =
            builderSupplier != null ? builderSupplier.get() : KmsClient.builder();

        // We can't just use computeIfAbsent as we need to avoid leaking KMS clients if we're asked
        // to decrypt
        // an EDK with a bogus region in its ARN. So we'll install a request handler to identify the
        // first
        // successful call, and cache it when we see that.
        final RequestClientCacher cacher = new RequestClientCacher(clientCache, region);
        KmsClient client =
            builder
                .region(region)
                .overrideConfiguration(config -> config.addExecutionInterceptor(cacher))
                .build();

        return cacher.setClient(client);
      };
    }

    /**
     * The AWS SDK has a default process for evaluating the default Region. This returns null if no
     * default region is found. Because a default region _may_ not be needed.
     */
    private static Region getSdkDefaultRegion() {
      try {
        return new DefaultAwsRegionProviderChain().getRegion();
      } catch (SdkClientException ex) {
        return null;
      }
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
  // # On initialization the caller MUST provide:
  private AwsKmsMrkAwareMasterKeyProvider(
      RegionalClientSupplier supplier,
      Region defaultRegion,
      List<String> keyIds,
      List<String> grantTokens,
      boolean isDiscovery,
      DiscoveryFilter discoveryFilter,
      Region discoveryMrkRegion) {
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
    /* Precondition: A region is required to contact AWS KMS.
     * This is an edge case because the default region will be the same as the SDK default,
     * but it is still possible.
     */
    if (!isDiscovery
        && defaultRegion == null
        && keyIds.stream().map(AwsKmsCmkArnInfo::parseInfoFromKeyArn).anyMatch(Objects::isNull)) {
      throw new AwsCryptoException(
          "Can't use non-ARN key identifiers or aliases when " + "no default region is set");
    }
    /* Precondition: Discovery filter is only valid in discovery mode. */
    if (!isDiscovery && discoveryFilter != null) {
      throw new IllegalArgumentException(
          "Strict mode cannot be configured with a " + "discovery filter.");
    }
    /* Precondition: Discovery mode can not have any keys to filter. */
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
            /* Postcondition: Filter out duplicate resources that are not multi-region keys.
             * I expect only have duplicates of specific multi-region keys.
             * In JSON something like
             * {
             *      "mrk-edb7fe6942894d32ac46dbb1c922d574" : [
             *          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
             *          "arn:aws:kms:us-east-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"
             *      ]
             *  }
             */
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
    /* Check for early return (Postcondition): Non-ARNs may be raw resources.
     * Raw aliases ('alias/my-key')
     * or key ids ('mrk-edb7fe6942894d32ac46dbb1c922d574').
     */
    if (info == null) return identifier;

    /* Check for early return (Postcondition): Return the identifier for non-key resource types.
     * I only care about duplicate multi-region *keys*.
     * Any other resource type
     * should get filtered out.
     * I return the entire identifier
     * on the off chance that
     * a customer has created
     * an alias with a name `mrk-*`.
     * This way such an alias
     * can never accidentally
     * collided with an existing multi-region key
     * or a duplicate alias.
     */
    if (!info.getResourceType().equals("key")) {
      return identifier;
    }

    /* Postcondition: Return the key id.
     * This will be used
     * to find different regional replicas of
     * the same multi-region key
     * because the key id for replicas is always the same.
     */
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
    /* Precondition: Discovery mode requires requestedKeyArn be an ARN.
     * This function is called on the encrypt path.
     * It _may_ be the case that a raw key id, for example, was configured.
     */
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

    final Region region_ =
        extractRegion(
            defaultRegion_, discoveryMrkRegion_, matchedArn, requestedKeyArnInfo, isDiscovery_);

    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // # An AWS KMS client
    // # MUST be obtained by calling the regional client supplier with this
    // # AWS Region.
    KmsClient client = regionalClientSupplier_.getClient(region_);

    String keyIdentifier =
        isDiscovery_
            // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
            // # In discovery mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
            // # master-key.md) MUST be returned configured with
            ? requestedKeyArnInfo.toString(region_.id())
            // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
            // # In strict mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
            // # master-key.md) MUST be returned configured with
            : matchedArn.get();

    final AwsKmsMrkAwareMasterKey result =
        AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, this);
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
  static Region extractRegion(
      final Region defaultRegion,
      final Region discoveryMrkRegion,
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
      return Region.of(requestedKeyArnInfo.getRegion());
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
    return Region.of(parseInfoFromKeyArn(matchedArn.get()).getRegion());
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
