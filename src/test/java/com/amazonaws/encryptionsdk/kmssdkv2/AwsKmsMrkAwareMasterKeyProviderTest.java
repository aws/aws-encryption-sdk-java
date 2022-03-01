// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kmssdkv2;

import static com.amazonaws.encryptionsdk.internal.AwsKmsCmkArnInfo.parseInfoFromKeyArn;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilter;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.jupiter.api.DisplayName;
import org.junit.runner.RunWith;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;

@RunWith(Enclosed.class)
public class AwsKmsMrkAwareMasterKeyProviderTest {

  public static class getResourceForResourceTypeKey {
    @Test
    @DisplayName("Postcondition: Return the key id.")
    public void basic_use() {
      assertEquals(
          "mrk-edb7fe6942894d32ac46dbb1c922d574",
          AwsKmsMrkAwareMasterKeyProvider.getResourceForResourceTypeKey(
              "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"));
    }

    @Test
    @DisplayName("Check for early return (Postcondition): Non-ARNs may be raw resources.")
    public void not_an_arn() {
      assertEquals(
          "mrk-edb7fe6942894d32ac46dbb1c922d574",
          AwsKmsMrkAwareMasterKeyProvider.getResourceForResourceTypeKey(
              "mrk-edb7fe6942894d32ac46dbb1c922d574"));
      final String malformed = "aws:kms:us-west-2::key/garbage";
      assertEquals(
          malformed, AwsKmsMrkAwareMasterKeyProvider.getResourceForResourceTypeKey(malformed));
    }

    @Test
    @DisplayName(
        "Check for early return (Postcondition): Return the identifier for non-key resource types.")
    public void not_a_key() {
      final String alias = "arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt";
      assertEquals(alias, AwsKmsMrkAwareMasterKeyProvider.getResourceForResourceTypeKey(alias));
    }
  }

  public static class assertMrksAreUnique {
    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    // = type=test
    // # The caller MUST provide:
    public void basic_use() {
      AwsKmsMrkAwareMasterKeyProvider.assertMrksAreUnique(
          Arrays.asList(
              "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"));
    }

    @Test
    public void no_duplicates() {
      // = compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
      // = type=test
      // # If there are zero duplicate resource ids between the multi-region
      // # keys, this function MUST exit successfully
      AwsKmsMrkAwareMasterKeyProvider.assertMrksAreUnique(
          Arrays.asList(
              "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
              "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    // = type=test
    // # If the list does not contain any multi-Region keys (aws-kms-key-
    // # arn.md#identifying-an-aws-kms-multi-region-key) this function MUST
    // # exit successfully.
    public void no_mrks_at_all() {
      AwsKmsMrkAwareMasterKeyProvider.assertMrksAreUnique(
          Arrays.asList(
              "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f",
              "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"));
    }

    @Test
    @DisplayName("Postcondition: Filter out duplicate resources that are not multi-region keys.")
    public void non_mrk_duplicates_ok() {
      AwsKmsMrkAwareMasterKeyProvider.assertMrksAreUnique(
          Arrays.asList(
              "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
              "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f",
              "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f",
              "arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt",
              "arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt"));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    // = type=test
    // # If any duplicate multi-region resource ids exist, this function MUST
    // # yield an error that includes all identifiers with duplicate resource
    // # ids not only the first duplicate found.
    public void no_duplicate_mrks() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              AwsKmsMrkAwareMasterKeyProvider.assertMrksAreUnique(
                  Arrays.asList(
                      "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                      "arn:aws:kms:us-east-1:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574")));
    }
  }

  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
  // = type=test
  // # On initialization the caller MUST provide:
  public static class AwsKmsMrkAwareMasterKeyProviderBuilderTests {
    @Test
    public void basic_use() {
      final AwsKmsMrkAwareMasterKeyProvider strict =
          AwsKmsMrkAwareMasterKeyProvider.builder()
              .buildStrict(
                  "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574");
      final AwsKmsMrkAwareMasterKeyProvider discovery =
          AwsKmsMrkAwareMasterKeyProvider.builder().buildDiscovery();

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.5
      // = type=test
      // # MUST implement the Master Key Provider Interface (../master-key-
      // # provider-interface.md#interface)
      assertTrue(MasterKeyProvider.class.isInstance(strict));
      assertTrue(MasterKeyProvider.class.isInstance(discovery));

      // These are not testable because of how the builder is structured.
      //
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
      // = type=test
      // # A discovery filter MUST NOT be configured in strict mode.
      //
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
      // = type=test
      // # A default MRK Region MUST NOT be configured in strict mode.
      //
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
      // = type=test
      // # In
      // # discovery mode if a default MRK Region is not configured the AWS SDK
      // # Default Region MUST be used.
      //
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
      // = type=test
      // # The key id list MUST be empty in discovery mode.
      //
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
      // = type=test
      // # The regional client
      // # supplier MUST be defined in discovery mode.
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
    // = type=test
    // # The key id list MUST NOT be empty or null in strict mode.
    public void no_noop() {
      assertThrows(
          IllegalArgumentException.class,
          () -> AwsKmsMrkAwareMasterKeyProvider.builder().buildStrict());
      assertThrows(
          IllegalArgumentException.class,
          () -> AwsKmsMrkAwareMasterKeyProvider.builder().buildStrict(new ArrayList<String>()));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
    // = type=test
    // # The key id
    // # list MUST NOT contain any null or empty string values.
    public void no_null_identifiers() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              AwsKmsMrkAwareMasterKeyProvider.builder()
                  .buildStrict(
                      "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                      ""));

      assertThrows(
          IllegalArgumentException.class,
          () ->
              AwsKmsMrkAwareMasterKeyProvider.builder()
                  .buildStrict(
                      "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                      null));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
    // = type=test
    // # All AWS KMS
    // # key identifiers are be passed to Assert AWS KMS MRK are unique (aws-
    // # kms-mrk-are-unique.md#Implementation) and the function MUST return
    // # success.
    public void no_duplicate_mrks() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              AwsKmsMrkAwareMasterKeyProvider.builder()
                  .buildStrict(
                      "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                      "arn:aws:kms:us-east-1:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"));
    }

    @Test
    @DisplayName("Precondition: A region is required to contact AWS KMS.")
    public void always_need_a_region() {
      assertThrows(
          AwsCryptoException.class,
          () ->
              AwsKmsMrkAwareMasterKeyProvider.builder()
                  .defaultRegion(null)
                  .buildStrict("mrk-edb7fe6942894d32ac46dbb1c922d574"));

      AwsKmsMrkAwareMasterKeyProvider.builder()
          .defaultRegion(Region.US_EAST_1)
          .buildStrict("mrk-edb7fe6942894d32ac46dbb1c922d574");
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
    // = type=test
    // # If an AWS SDK Default Region can not be
    // # obtained initialization MUST fail.
    public void discovery_region_can_not_be_null() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              AwsKmsMrkAwareMasterKeyProvider.builder()
                  // need to force the default region to `null`
                  // otherwise it may pick one up from the environment.
                  .defaultRegion(null)
                  .discoveryMrkRegion(null)
                  .buildDiscovery());
    }

    @Test
    @DisplayName("Precondition: Discovery filter is only valid in discovery mode.")
    public void strict_cannot_have_discovery_filter() {
      assertThrows(
          IllegalArgumentException.class,
          () -> {
            AwsKmsMrkAwareMasterKeyProvider mkp =
                AwsKmsMrkAwareMasterKeyProvider.builder()
                    .buildStrict(
                        "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574");

            Field field = mkp.getClass().getDeclaredField("discoveryFilter_");
            field.setAccessible(true);
            DiscoveryFilter filter = new DiscoveryFilter("partition", "accountId1");
            field.set(mkp, filter);
            field.setAccessible(false);

            mkp.withGrantTokens("token1", "token2");
          });
    }

    @Test
    @DisplayName("Precondition: Discovery mode can not have any keys to filter.")
    public void discovery_cannot_have_any_keys() {
      assertThrows(
          IllegalArgumentException.class,
          () -> {
            AwsKmsMrkAwareMasterKeyProvider mkp =
                AwsKmsMrkAwareMasterKeyProvider.builder().buildDiscovery();

            Field field = mkp.getClass().getDeclaredField("keyIds_");
            field.setAccessible(true);
            List<String> keyIds = Arrays.asList("keyId1", "keyId2");
            field.set(mkp, keyIds);
            field.setAccessible(false);

            mkp.withGrantTokens("token1", "token2");
          });
    }

    @Test
    public void get_grant_tokens() {
      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder().buildDiscovery();
      mkp = mkp.withGrantTokens("token1", "token2");
      assert (mkp.getGrantTokens()).contains("token1");
      assert (mkp.getGrantTokens()).contains("token2");
    }

    @Test
    public void basic_credentials_and_builder() {
      AwsCredentialsProvider credsProvider =
          StaticCredentialsProvider.create(AwsBasicCredentials.create("asdf", "qwer"));
      AwsKmsMrkAwareMasterKeyProvider.builder()
          .builderSupplier(() -> KmsClient.builder().credentialsProvider(credsProvider))
          .buildDiscovery();
    }
  }

  public static class extractRegion {

    @Test
    public void basic_use() {
      final Region test =
          AwsKmsMrkAwareMasterKeyProvider.extractRegion(
              Region.US_EAST_1,
              Region.US_EAST_2,
              Optional.of(
                  "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
              parseInfoFromKeyArn(
                  "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
              false);

      assertEquals(Region.US_WEST_2, test);
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // = type=test
    // # If the requested AWS KMS key identifier is not a well formed ARN the
    // # AWS Region MUST be the configured default region this SHOULD be
    // # obtained from the AWS SDK.
    public void not_an_arn() {
      final Region test =
          AwsKmsMrkAwareMasterKeyProvider.extractRegion(
              Region.US_EAST_1,
              Region.US_EAST_2,
              Optional.empty(),
              parseInfoFromKeyArn("mrk-edb7fe6942894d32ac46dbb1c922d574"),
              false);

      assertEquals(Region.US_EAST_1, test);
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // = type=test
    // # Otherwise if the requested AWS KMS key
    // # identifier is identified as a multi-Region key (aws-kms-key-
    // # arn.md#identifying-an-aws-kms-multi-region-key), then AWS Region MUST
    // # be the region from the AWS KMS key ARN stored in the provider info
    // # from the encrypted data key.
    public void not_an_mrk() {
      final Region test =
          AwsKmsMrkAwareMasterKeyProvider.extractRegion(
              Region.US_EAST_1,
              Region.US_EAST_2,
              Optional.of(
                  "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"),
              parseInfoFromKeyArn(
                  "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"),
              false);

      assertEquals(Region.US_WEST_2, test);

      final Region test2 =
          AwsKmsMrkAwareMasterKeyProvider.extractRegion(
              Region.US_EAST_1,
              Region.US_EAST_2,
              Optional.of("arn:aws:kms:us-west-2:658956600833:alias/mrk-nasty"),
              parseInfoFromKeyArn("arn:aws:kms:us-west-2:658956600833:alias/mrk-nasty"),
              false);

      assertEquals(Region.US_WEST_2, test2);
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // = type=test
    // # Otherwise if the mode is discovery then
    // # the AWS Region MUST be the discovery MRK region.
    public void mrk_in_discovery() {
      final Region test =
          AwsKmsMrkAwareMasterKeyProvider.extractRegion(
              Region.US_EAST_1,
              Region.US_EAST_2,
              Optional.empty(),
              parseInfoFromKeyArn(
                  "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
              true);

      assertEquals(Region.US_EAST_2, test);
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // = type=test
    // # Finally if the
    // # provider info is identified as a multi-Region key (aws-kms-key-
    // # arn.md#identifying-an-aws-kms-multi-region-key) the AWS Region MUST
    // # be the region from the AWS KMS key in the configured key ids matched
    // # to the requested AWS KMS key by using AWS KMS MRK Match for Decrypt
    // # (aws-kms-mrk-match-for-decrypt.md#implementation).
    public void fuzzy_match_mrk() {
      final Region test =
          AwsKmsMrkAwareMasterKeyProvider.extractRegion(
              Region.US_EAST_1,
              Region.US_EAST_2,
              Optional.of(
                  "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
              parseInfoFromKeyArn(
                  "arn:aws:kms:us-west-1:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
              false);

      assertEquals(Region.US_WEST_2, test);
    }
  }

  public static class getMasterKey {
    @Test
    public void basic_use() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final KmsClient client = spy(new MockKmsClient());
      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder()
              .customRegionalClientSupplier(supplier)
              .buildStrict(identifier);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
      // = type=test
      // # The input MUST be the same as the Master Key Provider Get Master Key
      // # (../master-key-provider-interface.md#get-master-key) interface.
      AwsKmsMrkAwareMasterKey test = mkp.getMasterKey("aws-kms", identifier);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
      // = type=test
      // # The output MUST be the same as the Master Key Provider Get Master Key
      // # (../master-key-provider-interface.md#get-master-key) interface.
      assertTrue(AwsKmsMrkAwareMasterKey.class.isInstance((test)));

      assertEquals(identifier, test.getKeyId());
      verify(supplier, times(1)).getClient(Region.US_WEST_2);
    }

    @Test
    public void basic_mrk_use() {
      final String configuredIdentifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final String requestedIdentifier =
          "arn:aws:kms:us-east-1:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final KmsClient client = spy(new MockKmsClient());
      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder()
              .customRegionalClientSupplier(supplier)
              .buildStrict(configuredIdentifier);

      AwsKmsMrkAwareMasterKey test = mkp.getMasterKey("aws-kms", requestedIdentifier);

      assertEquals(configuredIdentifier, test.getKeyId());
      verify(supplier, times(1)).getClient(Region.US_WEST_2);
    }

    @Test
    public void other_basic_uses() {
      final KmsClient client = spy(new MockKmsClient());
      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      // A raw alias is a valid configuration for encryption
      final String rawAliasIdentifier = "alias/my-alias";
      AwsKmsMrkAwareMasterKeyProvider.builder()
          .customRegionalClientSupplier(supplier)
          .buildStrict(rawAliasIdentifier)
          .getMasterKey("aws-kms", rawAliasIdentifier);

      // A raw alias is a valid configuration for encryption
      final String rawKeyIdentifier = "mrk-edb7fe6942894d32ac46dbb1c922d574";
      AwsKmsMrkAwareMasterKeyProvider.builder()
          .customRegionalClientSupplier(supplier)
          .buildStrict(rawKeyIdentifier)
          .getMasterKey("aws-kms", rawKeyIdentifier);
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // = type=test
    // # The function MUST only provide master keys if the input provider id
    // # equals "aws-kms".
    public void only_this_provider() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final KmsClient client = spy(new MockKmsClient());
      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder()
              .customRegionalClientSupplier(supplier)
              .buildStrict(identifier);

      assertThrows(
          UnsupportedProviderException.class, () -> mkp.getMasterKey("not-aws-kms", identifier));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // = type=test
    // # In strict mode, the requested AWS KMS key ARN MUST
    // # match a member of the configured key ids by using AWS KMS MRK Match
    // # for Decrypt (aws-kms-mrk-match-for-decrypt.md#implementation)
    // # otherwise this function MUST error.
    public void no_key_id_match() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final KmsClient client = spy(new MockKmsClient());
      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      final AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder()
              .customRegionalClientSupplier(supplier)
              .buildStrict(identifier);

      assertThrows(
          NoSuchMasterKeyException.class,
          () -> mkp.getMasterKey("aws-kms", "does-not-match-configured"));
    }

    @Test
    @DisplayName("Precondition: Discovery mode requires requestedKeyArn be an ARN.")
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // = type=test
    // # In discovery mode, the requested
    // # AWS KMS key identifier MUST be a well formed AWS KMS ARN.
    public void discovery_request_must_be_arn() {
      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder().buildDiscovery();

      assertThrows(
          NoSuchMasterKeyException.class,
          () -> mkp.getMasterKey("aws-kms", "mrk-edb7fe6942894d32ac46dbb1c922d574"));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // = type=test
    // # In
    // # discovery mode if a discovery filter is configured the requested AWS
    // # KMS key ARN's "partition" MUST match the discovery filter's
    // # "partition" and the AWS KMS key ARN's "account" MUST exist in the
    // # discovery filter's account id set.
    public void discovery_filter_must_match() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final KmsClient client = spy(new MockKmsClient());
      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      assertThrows(
          NoSuchMasterKeyException.class,
          () ->
              AwsKmsMrkAwareMasterKeyProvider.builder()
                  .buildDiscovery(new DiscoveryFilter("aws", Arrays.asList("not-111122223333")))
                  .getMasterKey("aws-kms", identifier));

      assertThrows(
          NoSuchMasterKeyException.class,
          () ->
              AwsKmsMrkAwareMasterKeyProvider.builder()
                  .buildDiscovery(new DiscoveryFilter("not-aws", Arrays.asList("111122223333")))
                  .getMasterKey("aws-kms", identifier));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // = type=test
    // # In discovery mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
    // # master-key.md) MUST be returned configured with
    public void discovery_magic_to_make_the_region_match() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final KmsClient client = spy(new MockKmsClient());
      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder()
              .customRegionalClientSupplier(supplier)
              .discoveryMrkRegion(Region.of("my-region"))
              .buildDiscovery();

      AwsKmsMrkAwareMasterKey test = mkp.getMasterKey("aws-kms", identifier);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
      // = type=test
      // # An AWS KMS client
      // # MUST be obtained by calling the regional client supplier with this
      // # AWS Region.
      assertEquals(
          "arn:aws:kms:my-region:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
          test.getKeyId());
      verify(supplier, times(1)).getClient(Region.of("my-region"));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    // = type=test
    // # In strict mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
    // # master-key.md) MUST be returned configured with
    public void strict_mrk_region_match() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final String configIdentifier =
          "arn:aws:kms:us-east-1:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final KmsClient client = spy(new MockKmsClient());
      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder()
              .customRegionalClientSupplier(supplier)
              .buildStrict(configIdentifier);

      AwsKmsMrkAwareMasterKey test = mkp.getMasterKey("aws-kms", identifier);

      assertEquals(configIdentifier, test.getKeyId());
      verify(supplier, times(1)).getClient(Region.US_EAST_1);
    }
  }

  public static class decryptDataKey {

    @Test
    public void basic_use() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final byte[] cipherText = new byte[10];
      final EncryptedDataKey edk1 =
          new KeyBlob("aws-kms", identifier.getBytes(StandardCharsets.UTF_8), cipherText);
      final EncryptedDataKey edk2 =
          new KeyBlob("aws-kms", identifier.getBytes(StandardCharsets.UTF_8), cipherText);

      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      final KmsClient client = mock(KmsClient.class);
      when(client.decrypt((DecryptRequest) any()))
          .thenReturn(
              DecryptResponse.builder()
                  .keyId(identifier)
                  .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
                  .build());
      when(supplier.getClient(any())).thenReturn(client);

      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder()
              .customRegionalClientSupplier(supplier)
              .buildStrict(identifier)
              .withGrantTokens(GRANT_TOKENS);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
      // = type=test
      // # The input MUST be the same as the Master Key Provider Decrypt Data
      // # Key (../master-key-provider-interface.md#decrypt-data-key) interface.
      final DataKey<AwsKmsMrkAwareMasterKey> test =
          mkp.decryptDataKey(ALGORITHM_SUITE, Arrays.asList(edk1, edk2), ENCRYPTION_CONTEXT);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
      // = type=test
      // # For each encrypted data key in the filtered set, one at a time, the
      // # master key provider MUST call Get Master Key (aws-kms-mrk-aware-
      // # master-key-provider.md#get-master-key) with the encrypted data key's
      // # provider info as the AWS KMS key ARN.
      //
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
      // = type=test
      // # It MUST call Decrypt Data Key
      // # (aws-kms-mrk-aware-master-key.md#decrypt-data-key) on this master key
      // # with the input algorithm, this single encrypted data key, and the
      // # input encryption context.
      //
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
      // = type=test
      // # If the decrypt data key call is
      // # successful, then this function MUST return this result and not
      // # attempt to decrypt any more encrypted data keys.
      verify(client, times((1)))
          .decrypt(
              DecryptRequest.builder()
                  .overrideConfiguration(
                      builder -> builder.addApiName(AwsKmsMrkAwareMasterKey.API_NAME))
                  .grantTokens(GRANT_TOKENS)
                  .encryptionContext(ENCRYPTION_CONTEXT)
                  .keyId(identifier)
                  .ciphertextBlob(SdkBytes.fromByteArray(cipherText))
                  .build());

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
      // = type=test
      // # The output MUST be the same as the Master Key Provider Decrypt Data
      // # Key (../master-key-provider-interface.md#decrypt-data-key) interface.
      assertTrue(DataKey.class.isInstance(test));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
    // = type=test
    // # The set of encrypted data keys MUST first be filtered to match this
    // # master key's configuration.
    public void only_if_providers_match() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final EncryptedDataKey edk =
          new KeyBlob(
              "not-aws-kms", "not the identifier".getBytes(StandardCharsets.UTF_8), new byte[10]);

      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder().buildStrict(identifier);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
      // = type=test
      // # To match the encrypted data key's
      // # provider ID MUST exactly match the value "aws-kms".
      final CannotUnwrapDataKeyException test =
          assertThrows(
              "Unable to decrypt any data keys",
              CannotUnwrapDataKeyException.class,
              () -> mkp.decryptDataKey(ALGORITHM_SUITE, Arrays.asList(edk), ENCRYPTION_CONTEXT));
      assertEquals(0, test.getSuppressed().length);
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
    // = type=test
    // # Additionally
    // # each provider info MUST be a valid AWS KMS ARN (aws-kms-key-arn.md#a-
    // # valid-aws-kms-arn) with a resource type of "key".
    public void provider_info_must_be_arn() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final String aliasArn =
          "arn:aws:kms:us-west-2:111122223333:alias/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final EncryptedDataKey edk =
          new KeyBlob("aws-kms", aliasArn.getBytes(StandardCharsets.UTF_8), new byte[10]);

      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder().buildStrict(identifier);

      final IllegalStateException test =
          assertThrows(
              "Invalid provider info in message.",
              IllegalStateException.class,
              () -> mkp.decryptDataKey(ALGORITHM_SUITE, Arrays.asList(edk), ENCRYPTION_CONTEXT));
      assertEquals(0, test.getSuppressed().length);
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
    // = type=test
    // # If this attempt results in an error, then
    // # these errors MUST be collected.
    //
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
    // = type=test
    // # If all the input encrypted data keys have been processed then this
    // # function MUST yield an error that includes all the collected errors.
    public void exception_wrapped() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final EncryptedDataKey edk =
          new KeyBlob("aws-kms", identifier.getBytes(StandardCharsets.UTF_8), new byte[10]);

      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      final KmsClient client = mock(KmsClient.class);
      final String clientErrMsg = "asdf";
      when(client.decrypt((DecryptRequest) any()))
          .thenThrow(AwsServiceException.builder().message(clientErrMsg).build());
      when(supplier.getClient(any())).thenReturn(client);

      AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder()
              .customRegionalClientSupplier(supplier)
              .buildStrict(identifier);

      CannotUnwrapDataKeyException test =
          assertThrows(
              "Unable to decrypt any data keys",
              CannotUnwrapDataKeyException.class,
              () -> mkp.decryptDataKey(ALGORITHM_SUITE, Arrays.asList(edk), ENCRYPTION_CONTEXT));
      assertEquals(1, test.getSuppressed().length);
      Throwable fromMasterKey = Arrays.stream(test.getSuppressed()).findFirst().get();
      assertTrue(fromMasterKey instanceof CannotUnwrapDataKeyException);
      assertEquals(1, fromMasterKey.getSuppressed().length);
      Throwable fromClient = Arrays.stream(fromMasterKey.getSuppressed()).findFirst().get();
      assertTrue(fromClient instanceof AwsServiceException);
      assertTrue(fromClient.getMessage().startsWith(clientErrMsg));
    }
  }

  public static class clientFactory {
    @Test
    public void basic_use() {
      final ConcurrentHashMap<Region, KmsClient> cache = spy(new ConcurrentHashMap<>());
      final Region region = Region.of("asdf");
      final KmsClient test =
          AwsKmsMrkAwareMasterKeyProvider.Builder.clientFactory(cache, null).getClient(region);
      assertNotEquals(null, test);
      verify(cache, times(1)).containsKey(region);
    }

    @Test
    @DisplayName("Check for early return (Postcondition): If a client already exists, use that.")
    public void use_clients_that_exist() {
      final Region region = Region.of("asdf");
      final ConcurrentHashMap<Region, KmsClient> cache = spy(new ConcurrentHashMap<>());
      // Add something so we can verify that we get it
      final KmsClient client = mock(KmsClient.class);
      cache.put(region, client);

      final KmsClient test =
          AwsKmsMrkAwareMasterKeyProvider.Builder.clientFactory(cache, null).getClient(region);

      assertEquals(client, test);
    }

    @Test
    public void uses_builder_supplier() {
      final ConcurrentHashMap<Region, KmsClient> cache = spy(new ConcurrentHashMap<>());
      final Region region = Region.of("asdf");

      KmsClientBuilder builder = mock(KmsClientBuilder.class);
      KmsClient client = mock(KmsClient.class);
      ClientOverrideConfiguration.Builder overrideBuilder =
          mock(ClientOverrideConfiguration.Builder.class);

      when(builder.region(any())).thenReturn(builder);
      when(builder.build()).thenReturn(client);
      doAnswer(
              ans -> {
                Consumer<ClientOverrideConfiguration.Builder> consumer = ans.getArgument(0);
                consumer.accept(overrideBuilder);
                return builder;
              })
          .when(builder)
          .overrideConfiguration((Consumer<ClientOverrideConfiguration.Builder>) any());

      final KmsClient test =
          AwsKmsMrkAwareMasterKeyProvider.Builder.clientFactory(cache, () -> builder)
              .getClient(region);

      verify(builder, times(1)).build();
      verify(overrideBuilder, times(1)).addExecutionInterceptor(any());
      assertEquals(client, test);
    }
  }

  public static class getMasterKeysForEncryption {
    @Test
    public void basic_use() {
      final String identifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final KmsClient client = spy(new MockKmsClient());
      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(Region.US_WEST_2)).thenReturn(client);
      final MasterKeyRequest request = MasterKeyRequest.newBuilder().build();

      final AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder()
              .defaultRegion(Region.US_WEST_2)
              .customRegionalClientSupplier(supplier)
              .buildStrict(identifier);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
      // = type=test
      // # The input MUST be the same as the Master Key Provider Get Master Keys
      // # For Encryption (../master-key-provider-interface.md#get-master-keys-
      // # for-encryption) interface.
      //
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
      // = type=test
      // # The output MUST be the same as the Master Key Provider Get Master
      // # Keys For Encryption (../master-key-provider-interface.md#get-master-
      // # keys-for-encryption) interface.
      final List<AwsKmsMrkAwareMasterKey> test = mkp.getMasterKeysForEncryption(request);
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
      // = type=test
      // # If the configured mode is strict this function MUST return a
      // # list of master keys obtained by calling Get Master Key (aws-kms-mrk-
      // # aware-master-key-provider.md#get-master-key) for each AWS KMS key
      // # identifier in the configured key ids
      assertEquals(1, test.size());
      assertEquals(identifier, test.get(0).getKeyId());
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
    // = type=test
    // # If the configured mode is discovery the function MUST return an empty
    // # list.
    public void no_keys_is_empty_list() {
      final AwsKmsMrkAwareMasterKeyProvider mkp =
          AwsKmsMrkAwareMasterKeyProvider.builder().buildDiscovery();

      final List<AwsKmsMrkAwareMasterKey> test =
          mkp.getMasterKeysForEncryption(MasterKeyRequest.newBuilder().build());
      assertEquals(0, test.size());
    }
  }
}
