// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kmssdkv2;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilter;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.awscore.AwsRequest;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.core.ApiName;
import software.amazon.awssdk.core.SdkRequest;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.exception.ApiCallAttemptTimeoutException;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;

public class KMSProviderBuilderIntegrationTests {

  private static final String AWS_KMS_PROVIDER_ID = "aws-kms";

  private KmsClient testUSWestClient__;
  private KmsClient testEUCentralClient__;
  private RegionalClientSupplier testClientSupplier__;

  @Before
  public void setup() {
    testUSWestClient__ =
        spy(new ProxyKmsClient(KmsClient.builder().region(Region.US_WEST_2).build()));
    testEUCentralClient__ =
        spy(new ProxyKmsClient(KmsClient.builder().region(Region.EU_CENTRAL_1).build()));
    testClientSupplier__ =
        region -> {
          if (region == Region.US_WEST_2) {
            return testUSWestClient__;
          } else if (region == Region.EU_CENTRAL_1) {
            return testEUCentralClient__;
          } else {
            throw new AwsCryptoException(
                "test supplier only configured for us-west-2 and eu-central-1");
          }
        };
  }

  @Test
  public void whenBogusRegionsDecrypted_doesNotLeakClients() throws Exception {
    AtomicReference<ConcurrentHashMap<Region, KmsClient>> kmsCache = new AtomicReference<>();

    KmsMasterKeyProvider mkp =
        (new KmsMasterKeyProvider.Builder() {
              @Override
              protected void snoopClientCache(final ConcurrentHashMap<Region, KmsClient> map) {
                kmsCache.set(map);
              }
            })
            .buildDiscovery();

    try {
      mkp.decryptDataKey(
          CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256,
          Collections.singleton(
              new KeyBlob(
                  "aws-kms",
                  "arn:aws:kms:us-bogus-1:123456789010:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
                      .getBytes(StandardCharsets.UTF_8),
                  new byte[40])),
          new HashMap<>());
      fail("Expected CannotUnwrapDataKeyException");
    } catch (CannotUnwrapDataKeyException e) {
      // ok
    }

    assertTrue(kmsCache.get().isEmpty());
  }

  @Test
  public void whenOperationSuccessful_clientIsCached() {
    AtomicReference<ConcurrentHashMap<Region, KmsClient>> kmsCache = new AtomicReference<>();

    KmsMasterKeyProvider mkp =
        (new KmsMasterKeyProvider.Builder() {
              @Override
              protected void snoopClientCache(final ConcurrentHashMap<Region, KmsClient> map) {
                kmsCache.set(map);
              }
            })
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

    AwsCrypto.standard().encryptData(mkp, new byte[1]);

    KmsClient kms = kmsCache.get().get(Region.US_WEST_2);
    assertNotNull(kms);

    AwsCrypto.standard().encryptData(mkp, new byte[1]);

    // Cache entry should stay the same
    assertEquals(kms, kmsCache.get().get(Region.US_WEST_2));
  }

  // ============================================================================== GOOD

  @Test
  public void whenConstructedWithoutArguments_canUseMultipleRegions() throws Exception {
    KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder().buildDiscovery();

    for (String key : KMSTestFixtures.TEST_KEY_IDS) {
      byte[] ciphertext =
          AwsCrypto.standard()
              .encryptData(KmsMasterKeyProvider.builder().buildStrict(key), new byte[1])
              .getResult();

      AwsCrypto.standard().decryptData(mkp, ciphertext);
    }
  }

  @Test
  public void whenConstructedInStrictMode_encryptDecrypt() throws Exception {
    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(testClientSupplier__)
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

    byte[] ciphertext = AwsCrypto.standard().encryptData(mkp, new byte[1]).getResult();
    verify(testUSWestClient__, times(1)).generateDataKey((GenerateDataKeyRequest) any());

    AwsCrypto.standard().decryptData(mkp, ciphertext);
    verify(testUSWestClient__, times(1)).decrypt((DecryptRequest) any());
  }

  @Test
  public void whenConstructedInStrictMode_encryptDecryptMultipleCmks() throws Exception {
    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(testClientSupplier__)
            .buildStrict(KMSTestFixtures.US_WEST_2_KEY_ID, KMSTestFixtures.EU_CENTRAL_1_KEY_ID);

    byte[] ciphertext = AwsCrypto.standard().encryptData(mkp, new byte[1]).getResult();
    verify(testUSWestClient__, times(1)).generateDataKey((GenerateDataKeyRequest) any());
    verify(testEUCentralClient__, times(1)).encrypt((EncryptRequest) any());

    AwsCrypto.standard().decryptData(mkp, ciphertext);
    verify(testUSWestClient__, times(1)).decrypt((DecryptRequest) any());
  }

  @Test
  public void whenConstructedInStrictMode_encryptSingleBadKeyIdFails() throws Exception {
    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(testClientSupplier__)
            .defaultRegion(Region.US_WEST_2)
            .buildStrict(KMSTestFixtures.US_WEST_2_KEY_ID, "badKeyId");

    assertThrows(
        AwsCryptoException.class,
        () -> AwsCrypto.standard().encryptData(mkp, new byte[1]).getResult());
    verify(testUSWestClient__, times(1)).generateDataKey((GenerateDataKeyRequest) any());
    verify(testUSWestClient__, times(1)).encrypt((EncryptRequest) any());
  }

  @Test
  public void whenConstructedInStrictMode_decryptBadEDKFails() throws Exception {
    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(testClientSupplier__)
            .defaultRegion(Region.US_WEST_2)
            .buildStrict("badKeyId");

    final CryptoAlgorithm algSuite = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    final Map<String, String> encCtx = Collections.singletonMap("myKey", "myValue");
    final EncryptedDataKey badEDK =
        new KeyBlob(
            AWS_KMS_PROVIDER_ID,
            "badKeyId".getBytes(StandardCharsets.UTF_8),
            new byte[algSuite.getDataKeyLength()]);

    assertThrows(
        CannotUnwrapDataKeyException.class,
        () -> mkp.decryptDataKey(algSuite, Collections.singletonList(badEDK), encCtx));
    verify(testUSWestClient__, times(1)).decrypt((DecryptRequest) any());
  }

  @Test
  public void whenConstructedInDiscoveryMode_decrypt() throws Exception {
    KmsMasterKeyProvider singleCmkMkp =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(testClientSupplier__)
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);
    byte[] singleCmkCiphertext =
        AwsCrypto.standard().encryptData(singleCmkMkp, new byte[1]).getResult();

    KmsMasterKeyProvider mkpToTest =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(testClientSupplier__)
            .buildDiscovery();
    AwsCrypto.standard().decryptData(mkpToTest, singleCmkCiphertext);
    verify(testUSWestClient__, times(1)).decrypt((DecryptRequest) any());
  }

  @Test
  public void whenConstructedInDiscoveryMode_decryptBadEDKFails() throws Exception {
    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(testClientSupplier__)
            .defaultRegion(Region.US_WEST_2)
            .buildDiscovery();

    final CryptoAlgorithm algSuite = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    final Map<String, String> encCtx = Collections.singletonMap("myKey", "myValue");
    final EncryptedDataKey badEDK =
        new KeyBlob(
            AWS_KMS_PROVIDER_ID,
            "badKeyId".getBytes(StandardCharsets.UTF_8),
            new byte[algSuite.getDataKeyLength()]);

    assertThrows(
        CannotUnwrapDataKeyException.class,
        () -> mkp.decryptDataKey(algSuite, Collections.singletonList(badEDK), encCtx));
    verify(testUSWestClient__, times(1)).decrypt((DecryptRequest) any());
  }

  @Test
  public void whenConstructedWithDiscoveryFilter_decrypt() throws Exception {
    KmsMasterKeyProvider singleCmkMkp =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(testClientSupplier__)
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

    byte[] singleCmkCiphertext =
        AwsCrypto.standard().encryptData(singleCmkMkp, new byte[1]).getResult();

    KmsMasterKeyProvider mkpToTest =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(testClientSupplier__)
            .buildDiscovery(
                new DiscoveryFilter(
                    KMSTestFixtures.PARTITION, Arrays.asList(KMSTestFixtures.ACCOUNT_ID)));

    AwsCrypto.standard().decryptData(mkpToTest, singleCmkCiphertext);
    verify(testUSWestClient__, times(1)).decrypt((DecryptRequest) any());
  }

  @Test
  public void whenConstructedWithDiscoveryFilter_decryptBadEDKFails() throws Exception {
    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(testClientSupplier__)
            .defaultRegion(Region.US_WEST_2)
            .buildDiscovery(
                new DiscoveryFilter(
                    KMSTestFixtures.PARTITION, Arrays.asList(KMSTestFixtures.ACCOUNT_ID)));

    final CryptoAlgorithm algSuite = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    final Map<String, String> encCtx = Collections.singletonMap("myKey", "myValue");
    final String badARN = "arn:aws:kms:us-west-2:658956600833:key/badID";
    final EncryptedDataKey badEDK =
        new KeyBlob(
            AWS_KMS_PROVIDER_ID,
            badARN.getBytes(StandardCharsets.UTF_8),
            new byte[algSuite.getDataKeyLength()]);

    assertThrows(
        CannotUnwrapDataKeyException.class,
        () -> mkp.decryptDataKey(algSuite, Collections.singletonList(badEDK), encCtx));
    verify(testUSWestClient__, times(1)).decrypt((DecryptRequest) any());
  }

  @Test
  public void whenHandlerConfigured_handlerIsInvoked() throws Exception {
    ExecutionInterceptor interceptor =
        spy(
            new ExecutionInterceptor() {
              @Override
              public void beforeExecution(
                  Context.BeforeExecution context, ExecutionAttributes executionAttributes) {}
            });

    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .builderSupplier(
                () ->
                    KmsClient.builder()
                        .overrideConfiguration(
                            ClientOverrideConfiguration.builder()
                                .addExecutionInterceptor(interceptor)
                                .build()))
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

    AwsCrypto.standard().encryptData(mkp, new byte[1]);

    verify(interceptor).beforeExecution(any(), any());
  }

  @Test
  public void whenShortTimeoutSet_timesOut() throws Exception {
    // By setting a timeout of 1ms, it's not physically possible to complete both the us-west-2 and
    // eu-central-1
    // requests due to speed of light limits.
    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .builderSupplier(
                () ->
                    KmsClient.builder()
                        .overrideConfiguration(
                            ClientOverrideConfiguration.builder()
                                .apiCallTimeout(Duration.ofMillis(1))
                                .build()))
            .buildStrict(Arrays.asList(KMSTestFixtures.TEST_KEY_IDS));

    try {
      AwsCrypto.standard().encryptData(mkp, new byte[1]);
      fail("Expected exception");
    } catch (Exception e) {
      if (!(e instanceof ApiCallAttemptTimeoutException)
          && !(e instanceof ApiCallTimeoutException)) {
        throw e;
      }
    }
  }

  // ================================================= BAD

  @Test
  public void whenBuilderCloned_configurationIsRetained() throws Exception {
    // TODO: remove test of credentials provider since no longer domain of builder supplier
    AwsCredentialsProvider customProvider1 =
        spy(new ProxyCredentialsProvider(DefaultCredentialsProvider.builder().build()));
    AwsCredentialsProvider customProvider2 =
        spy(new ProxyCredentialsProvider(DefaultCredentialsProvider.builder().build()));

    KmsMasterKeyProvider.Builder builder =
        KmsMasterKeyProvider.builder()
            .builderSupplier(() -> KmsClient.builder().credentialsProvider(customProvider1));

    KmsMasterKeyProvider.Builder builder2 = builder.clone();

    // This will mutate the first builder to change the creds, but leave the clone unchanged.
    MasterKeyProvider<?> mkp2 =
        builder
            .builderSupplier(() -> KmsClient.builder().credentialsProvider(customProvider2))
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);
    MasterKeyProvider<?> mkp1 = builder2.buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

    CryptoResult<byte[], ?> result = AwsCrypto.standard().encryptData(mkp1, new byte[0]);

    verify(customProvider1, atLeastOnce()).resolveCredentials();
    verify(customProvider2, never()).resolveCredentials();

    reset(customProvider1, customProvider2);

    result = AwsCrypto.standard().encryptData(mkp2, new byte[0]);

    verify(customProvider1, never()).resolveCredentials();
    verify(customProvider2, atLeastOnce()).resolveCredentials();
  }

  @Test
  public void whenBuilderCloned_clientBuilderCustomizationIsRetained() throws Exception {
    ExecutionInterceptor interceptor =
        spy(
            new ExecutionInterceptor() {
              @Override
              public void beforeExecution(
                  Context.BeforeExecution context, ExecutionAttributes executionAttributes) {}
            });

    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .builderSupplier(
                () ->
                    KmsClient.builder()
                        .overrideConfiguration(
                            builder -> builder.addExecutionInterceptor(interceptor)))
            .clone()
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

    AwsCrypto.standard().encryptData(mkp, new byte[0]);

    verify(interceptor, atLeastOnce()).beforeExecution(any(), any());
  }

  @Test
  public void whenUserAgentsOverridden_originalUAsPreserved() throws Exception {
    ExecutionInterceptor interceptor =
        spy(
            new ExecutionInterceptor() {
              @Override
              public SdkRequest modifyRequest(
                  Context.ModifyRequest context, ExecutionAttributes executionAttributes) {
                if (!(context.request() instanceof AwsRequest)) {
                  return context.request();
                }

                AwsRequest awsRequest = (AwsRequest) context.request();
                AwsRequestOverrideConfiguration.Builder overrideConfiguration;
                if (awsRequest.overrideConfiguration().isPresent()) {
                  overrideConfiguration = awsRequest.overrideConfiguration().get().toBuilder();
                } else {
                  overrideConfiguration = AwsRequestOverrideConfiguration.builder();
                }

                AwsRequestOverrideConfiguration newConfig =
                    overrideConfiguration
                        .addApiName(ApiName.builder().name("NEW_API").version("0.0.1").build())
                        .build();

                awsRequest = awsRequest.toBuilder().overrideConfiguration(newConfig).build();
                return awsRequest;
              }

              @Override
              public void beforeTransmission(
                  Context.BeforeTransmission context, ExecutionAttributes executionAttributes) {
                // Just for spying
              }
            });

    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .builderSupplier(
                () ->
                    KmsClient.builder()
                        .overrideConfiguration(
                            ClientOverrideConfiguration.builder()
                                .addExecutionInterceptor(interceptor)
                                .build()))
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

    AwsCrypto.standard().encryptData(mkp, new byte[0]);

    verify(interceptor, atLeastOnce()).modifyRequest(any(), any());

    ArgumentCaptor<Context.BeforeTransmission> captor =
        ArgumentCaptor.forClass(Context.BeforeTransmission.class);
    verify(interceptor, atLeastOnce()).beforeTransmission(captor.capture(), any());

    String ua = captor.getValue().httpRequest().headers().get("User-Agent").get(0);

    assertTrue(ua.contains("NEW_API/0.0.1"));
    assertTrue(ua.contains(VersionInfo.loadUserAgent()));
  }

  @Test
  public void whenDefaultRegionSet_itIsUsedForBareKeyIds() throws Exception {
    // TODO: Need to set up a role to assume as bare key IDs are relative to the caller account
  }
}
