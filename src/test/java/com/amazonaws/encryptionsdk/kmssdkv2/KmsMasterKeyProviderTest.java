// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kmssdkv2;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilter;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.awscore.AwsRequest;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;

@RunWith(Enclosed.class)
public class KmsMasterKeyProviderTest {

  private static final String AWS_PARTITION = "aws";
  private static final String AWS_KMS_PROVIDER_ID = "aws-kms";
  private static final String OTHER_PARTITION = "not-aws";
  private static final String OTHER_PROVIDER_ID = "not-aws-kms";
  private static final String ACCOUNT_ID = "999999999999";
  private static final String OTHER_ACCOUNT_ID = "000000000000";

  private static final String KEY_ID_1 =
      "arn:"
          + AWS_PARTITION
          + ":kms:us-east-1:"
          + ACCOUNT_ID
          + ":key/01234567-89ab-cdef-fedc-ba9876543210";
  private static final String KEY_ID_2 =
      "arn:"
          + AWS_PARTITION
          + ":kms:us-east-1:"
          + ACCOUNT_ID
          + ":key/01234567-89ab-cdef-fedc-ba9876543211";
  private static final String KEY_ID_3 =
      "arn:"
          + AWS_PARTITION
          + ":kms:us-east-1:"
          + ACCOUNT_ID
          + ":key/01234567-89ab-cdef-fedc-ba9876543212";
  private static final String KEY_ID_4 =
      "arn:"
          + AWS_PARTITION
          + ":kms:us-east-1:"
          + OTHER_ACCOUNT_ID
          + ":key/01234567-89ab-cdef-fedc-ba9876543210";
  private static final String KEY_ID_5 =
      "arn:"
          + OTHER_PARTITION
          + ":kms:us-east-1:"
          + ACCOUNT_ID
          + ":key/01234567-89ab-cdef-fedc-ba9876543210";

  private static final CryptoAlgorithm ALGORITHM_SUITE =
      CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
  private static final Map<String, String> ENCRYPTION_CONTEXT =
      Collections.singletonMap("myKey", "myValue");

  private static final EncryptedDataKey EDK_ID_1 =
      new KeyBlob(
          AWS_KMS_PROVIDER_ID,
          KEY_ID_1.getBytes(StandardCharsets.UTF_8),
          generate(ALGORITHM_SUITE.getDataKeyLength()));
  private static final EncryptedDataKey EDK_ID_1_OTHER_CIPHERTEXT =
      new KeyBlob(
          AWS_KMS_PROVIDER_ID,
          KEY_ID_1.getBytes(StandardCharsets.UTF_8),
          generate(ALGORITHM_SUITE.getDataKeyLength()));
  private static final EncryptedDataKey EDK_ID_2 =
      new KeyBlob(
          AWS_KMS_PROVIDER_ID,
          KEY_ID_2.getBytes(StandardCharsets.UTF_8),
          generate(ALGORITHM_SUITE.getDataKeyLength()));
  private static final EncryptedDataKey EDK_ID_3 =
      new KeyBlob(
          AWS_KMS_PROVIDER_ID,
          KEY_ID_3.getBytes(StandardCharsets.UTF_8),
          generate(ALGORITHM_SUITE.getDataKeyLength()));
  private static final EncryptedDataKey EDK_NON_ARN =
      new KeyBlob(
          AWS_KMS_PROVIDER_ID,
          "someAlias".getBytes(StandardCharsets.UTF_8),
          generate(ALGORITHM_SUITE.getDataKeyLength()));
  private static final EncryptedDataKey EDK_EMPTY_PROVIDER =
      new KeyBlob(
          "",
          "someId".getBytes(StandardCharsets.UTF_8),
          generate(ALGORITHM_SUITE.getDataKeyLength()));
  private static final EncryptedDataKey EDK_OTHER_PROVIDER =
      new KeyBlob(
          OTHER_PROVIDER_ID,
          "someId".getBytes(StandardCharsets.UTF_8),
          generate(ALGORITHM_SUITE.getDataKeyLength()));
  private static final EncryptedDataKey EDK_OTHER_ACCOUNT =
      new KeyBlob(
          AWS_KMS_PROVIDER_ID,
          KEY_ID_4.getBytes(StandardCharsets.UTF_8),
          generate(ALGORITHM_SUITE.getDataKeyLength()));
  private static final EncryptedDataKey EDK_OTHER_PARTITION =
      new KeyBlob(
          AWS_KMS_PROVIDER_ID,
          KEY_ID_5.getBytes(StandardCharsets.UTF_8),
          generate(ALGORITHM_SUITE.getDataKeyLength()));

  @RunWith(Parameterized.class)
  public static class ParameterizedDecryptTest {
    MKPTestConfiguration mkpConfig;
    List<EncryptedDataKey> inputEDKs;
    List<EncryptedDataKey> decryptableEDKs;

    private static class MKPTestConfiguration {
      // instance vars are public for easier access during testing
      public boolean isDiscovery;
      public DiscoveryFilter discoveryFilter;
      public List<String> keyIds;

      public MKPTestConfiguration(
          boolean isDiscovery, DiscoveryFilter discoveryFilter, List<String> keyIds) {
        this.isDiscovery = isDiscovery;
        this.discoveryFilter = discoveryFilter;
        this.keyIds = keyIds;
      }
    }

    public ParameterizedDecryptTest(
        MKPTestConfiguration mkpConfig,
        List<EncryptedDataKey> inputEDKs,
        List<EncryptedDataKey> decryptableEDKs) {
      this.mkpConfig = mkpConfig;
      this.inputEDKs = inputEDKs;
      this.decryptableEDKs = decryptableEDKs;
    }

    @Parameterized.Parameters(name = "{index}: mkpConfig={0}, inputEDKs={1}, decryptableEDKs={2}")
    public static Collection<Object[]> testCases() {
      // Create MKP configuration options to test against
      MKPTestConfiguration strict_oneCMK =
          new MKPTestConfiguration(false, null, Arrays.asList(KEY_ID_1));
      MKPTestConfiguration strict_twoCMKs =
          new MKPTestConfiguration(false, null, Arrays.asList(KEY_ID_1, KEY_ID_2));
      MKPTestConfiguration explicitDiscovery = new MKPTestConfiguration(true, null, null);
      MKPTestConfiguration explicitDiscovery_filter =
          new MKPTestConfiguration(
              true, new DiscoveryFilter(AWS_PARTITION, Arrays.asList(ACCOUNT_ID)), null);

      // Define all test cases
      Collection<Object[]> testCases =
          Arrays.asList(
              new Object[][] {
                // Test cases where no EDKs are expected to be decrypted
                {strict_oneCMK, Collections.emptyList(), Collections.emptyList()},
                {strict_oneCMK, Arrays.asList(EDK_ID_2), Collections.emptyList()},
                {strict_oneCMK, Arrays.asList(EDK_ID_2, EDK_ID_3), Collections.emptyList()},
                {strict_twoCMKs, Collections.emptyList(), Collections.emptyList()},
                {strict_twoCMKs, Arrays.asList(EDK_ID_3), Collections.emptyList()},
                {
                  strict_twoCMKs,
                  Arrays.asList(EDK_ID_3, EDK_OTHER_PROVIDER),
                  Collections.emptyList()
                },
                {explicitDiscovery, Collections.emptyList(), Collections.emptyList()},
                {explicitDiscovery, Arrays.asList(EDK_OTHER_PROVIDER), Collections.emptyList()},
                {explicitDiscovery, Arrays.asList(EDK_EMPTY_PROVIDER), Collections.emptyList()},
                {
                  explicitDiscovery,
                  Arrays.asList(EDK_OTHER_PROVIDER, EDK_EMPTY_PROVIDER),
                  Collections.emptyList()
                },
                {explicitDiscovery_filter, Collections.emptyList(), Collections.emptyList()},
                {
                  explicitDiscovery_filter,
                  Arrays.asList(EDK_OTHER_PROVIDER),
                  Collections.emptyList()
                },
                {
                  explicitDiscovery_filter,
                  Arrays.asList(EDK_EMPTY_PROVIDER),
                  Collections.emptyList()
                },
                {explicitDiscovery_filter, Arrays.asList(EDK_NON_ARN), Collections.emptyList()},
                {
                  explicitDiscovery_filter,
                  Arrays.asList(EDK_OTHER_PARTITION),
                  Collections.emptyList()
                },
                {
                  explicitDiscovery_filter,
                  Arrays.asList(EDK_OTHER_ACCOUNT),
                  Collections.emptyList()
                },
                {
                  explicitDiscovery_filter,
                  Arrays.asList(EDK_OTHER_PROVIDER, EDK_EMPTY_PROVIDER),
                  Collections.emptyList()
                },

                // Test cases where one EDK is expected to be decryptable
                {strict_oneCMK, Arrays.asList(EDK_ID_1), Arrays.asList(EDK_ID_1)},
                {strict_oneCMK, Arrays.asList(EDK_ID_2, EDK_ID_1), Arrays.asList(EDK_ID_1)},
                {strict_oneCMK, Arrays.asList(EDK_ID_1, EDK_ID_2), Arrays.asList(EDK_ID_1)},
                {strict_twoCMKs, Arrays.asList(EDK_ID_1), Arrays.asList(EDK_ID_1)},
                {strict_twoCMKs, Arrays.asList(EDK_ID_2), Arrays.asList(EDK_ID_2)},
                {strict_twoCMKs, Arrays.asList(EDK_ID_3, EDK_ID_1), Arrays.asList(EDK_ID_1)},
                {strict_twoCMKs, Arrays.asList(EDK_ID_1, EDK_ID_3), Arrays.asList(EDK_ID_1)},
                {explicitDiscovery, Arrays.asList(EDK_ID_1), Arrays.asList(EDK_ID_1)},
                {
                  explicitDiscovery,
                  Arrays.asList(EDK_OTHER_PROVIDER, EDK_ID_1),
                  Arrays.asList(EDK_ID_1)
                },
                {
                  explicitDiscovery,
                  Arrays.asList(EDK_ID_1, EDK_OTHER_PROVIDER),
                  Arrays.asList(EDK_ID_1)
                },
                {explicitDiscovery_filter, Arrays.asList(EDK_ID_1), Arrays.asList(EDK_ID_1)},
                {
                  explicitDiscovery_filter,
                  Arrays.asList(EDK_OTHER_ACCOUNT, EDK_ID_1),
                  Arrays.asList(EDK_ID_1)
                },
                {
                  explicitDiscovery_filter,
                  Arrays.asList(EDK_ID_1, EDK_OTHER_ACCOUNT),
                  Arrays.asList(EDK_ID_1)
                },

                // Test cases where multiple EDKs are expected to be decryptable
                {
                  strict_oneCMK,
                  Arrays.asList(EDK_ID_1, EDK_ID_1_OTHER_CIPHERTEXT),
                  Arrays.asList(EDK_ID_1, EDK_ID_1_OTHER_CIPHERTEXT)
                },
                {
                  strict_twoCMKs,
                  Arrays.asList(EDK_ID_1, EDK_ID_2),
                  Arrays.asList(EDK_ID_1, EDK_ID_2)
                },
                {
                  explicitDiscovery,
                  Arrays.asList(EDK_ID_1, EDK_ID_2),
                  Arrays.asList(EDK_ID_1, EDK_ID_2)
                },
                {
                  explicitDiscovery_filter,
                  Arrays.asList(EDK_ID_1, EDK_ID_2),
                  Arrays.asList(EDK_ID_1, EDK_ID_2)
                },
              });
      return testCases;
    }

    @SuppressWarnings("deprecation")
    private KmsMasterKeyProvider constructMKPForTest(
        MKPTestConfiguration mkpConfig, RegionalClientSupplier supplier) {
      KmsMasterKeyProvider.Builder builder =
          KmsMasterKeyProvider.builder().customRegionalClientSupplier(supplier);

      KmsMasterKeyProvider mkp;
      if (mkpConfig.isDiscovery && mkpConfig.discoveryFilter == null) {
        mkp = builder.buildDiscovery();
      } else if (mkpConfig.isDiscovery) {
        mkp = builder.buildDiscovery(mkpConfig.discoveryFilter);
      } else {
        mkp = builder.buildStrict(mkpConfig.keyIds);
      }

      return mkp;
    }

    @Test
    public void testDecrypt() throws Exception {
      MockKmsClient client = spy(new MockKmsClient());
      RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      // create MKP to test
      KmsMasterKeyProvider mkp = constructMKPForTest(mkpConfig, supplier);

      // if we expect none of them to decrypt, just test that we get the correct
      // failure and KMS was not called
      if (decryptableEDKs.size() <= 0) {
        assertThrows(
            CannotUnwrapDataKeyException.class,
            () -> mkp.decryptDataKey(ALGORITHM_SUITE, inputEDKs, ENCRYPTION_CONTEXT));

        ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
        verifyNoInteractions(client);
        return;
      }

      // Test that the mkp calls KMS for the first expected EDK
      EncryptedDataKey expectedEDK = decryptableEDKs.get(0);

      // mock KMS to return the KeyId for the expected EDK,
      // we verify that we call KMS with this KeyId, so this is ok
      DecryptResponse decryptResponse =
          DecryptResponse.builder()
              .keyId(new String(expectedEDK.getProviderInformation(), StandardCharsets.UTF_8))
              .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
              .build();
      doReturn(decryptResponse).when(client).decrypt(isA(DecryptRequest.class));

      DataKey<KmsMasterKey> dataKeyResult =
          mkp.decryptDataKey(ALGORITHM_SUITE, inputEDKs, ENCRYPTION_CONTEXT);

      ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
      verify(client, times(1)).decrypt(decrypt.capture());
      verifyNoMoreInteractions(client);

      DecryptRequest actualRequest = decrypt.getValue();
      assertArrayEquals(
          expectedEDK.getProviderInformation(),
          actualRequest.keyId().getBytes(StandardCharsets.UTF_8));
      assertEquals(ENCRYPTION_CONTEXT, actualRequest.encryptionContext());
      assertArrayEquals(
          expectedEDK.getEncryptedDataKey(), actualRequest.ciphertextBlob().asByteArray());
      assertApiName(actualRequest);

      assertArrayEquals(
          expectedEDK.getProviderInformation(), dataKeyResult.getProviderInformation());
      assertArrayEquals(expectedEDK.getEncryptedDataKey(), dataKeyResult.getEncryptedDataKey());
    }

    @Test
    public void testDecryptKMSFailsOnce() throws Exception {
      MockKmsClient client = spy(new MockKmsClient());
      RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      // create MKP to test
      KmsMasterKeyProvider mkp = constructMKPForTest(mkpConfig, supplier);

      // if we expect one or less KMS call, just test that we get the correct
      // failure and KMS was called the expected number of times
      if (decryptableEDKs.size() <= 1) {
        // Mock KMS to fail
        doThrow(AwsServiceException.builder().message("fail").build())
            .when(client)
            .decrypt(isA(DecryptRequest.class));

        assertThrows(
            CannotUnwrapDataKeyException.class,
            () -> mkp.decryptDataKey(ALGORITHM_SUITE, inputEDKs, ENCRYPTION_CONTEXT));

        ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(client, times(decryptableEDKs.size())).decrypt(decrypt.capture());
        return;
      }

      EncryptedDataKey expectedFailedEDK = decryptableEDKs.get(0);
      EncryptedDataKey expectedSuccessfulEDK = decryptableEDKs.get(1);

      // Mock KMS to fail the first call then succeed for the second call
      DecryptResponse decryptResponse =
          DecryptResponse.builder()
              .keyId(
                  new String(
                      expectedSuccessfulEDK.getProviderInformation(), StandardCharsets.UTF_8))
              .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
              .build();
      doThrow(AwsServiceException.builder().message("fail").build())
          .doReturn(decryptResponse)
          .when(client)
          .decrypt(isA(DecryptRequest.class));

      DataKey<KmsMasterKey> dataKeyResult =
          mkp.decryptDataKey(ALGORITHM_SUITE, inputEDKs, ENCRYPTION_CONTEXT);

      ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
      verify(client, times(2)).decrypt(decrypt.capture());
      verifyNoMoreInteractions(client);

      List<DecryptRequest> actualRequests = decrypt.getAllValues();
      DecryptRequest failedRequest = actualRequests.get(0);
      assertArrayEquals(
          expectedFailedEDK.getProviderInformation(),
          failedRequest.keyId().getBytes(StandardCharsets.UTF_8));
      assertEquals(ENCRYPTION_CONTEXT, failedRequest.encryptionContext());
      assertArrayEquals(
          expectedFailedEDK.getEncryptedDataKey(), failedRequest.ciphertextBlob().asByteArray());
      assertApiName(failedRequest);

      DecryptRequest successfulRequest = actualRequests.get(1);
      assertArrayEquals(
          expectedSuccessfulEDK.getProviderInformation(),
          successfulRequest.keyId().getBytes(StandardCharsets.UTF_8));
      assertEquals(ENCRYPTION_CONTEXT, successfulRequest.encryptionContext());
      assertArrayEquals(
          expectedSuccessfulEDK.getEncryptedDataKey(),
          successfulRequest.ciphertextBlob().asByteArray());
      assertApiName(successfulRequest);

      assertArrayEquals(
          expectedSuccessfulEDK.getProviderInformation(), dataKeyResult.getProviderInformation());
      assertArrayEquals(
          expectedSuccessfulEDK.getEncryptedDataKey(), dataKeyResult.getEncryptedDataKey());
    }

    private void assertApiName(AwsRequest request) {
      Optional<AwsRequestOverrideConfiguration> overrideConfig = request.overrideConfiguration();
      assertTrue(overrideConfig.isPresent());
      assertTrue(
          overrideConfig.get().apiNames().stream()
              .anyMatch(
                  api ->
                      api.name().equals(VersionInfo.apiName())
                          && api.version().equals(VersionInfo.versionNumber())));
    }
  }

  public static class NonParameterized {
    @Test
    public void testBuildStrictWithNoCMKs() throws Exception {
      RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);

      assertThrows(
          IllegalArgumentException.class,
          () ->
              KmsMasterKeyProvider.builder().customRegionalClientSupplier(supplier).buildStrict());

      assertThrows(
          IllegalArgumentException.class,
          () ->
              KmsMasterKeyProvider.builder()
                  .customRegionalClientSupplier(supplier)
                  .buildStrict(Collections.emptyList()));

      assertThrows(
          IllegalArgumentException.class,
          () ->
              KmsMasterKeyProvider.builder()
                  .customRegionalClientSupplier(supplier)
                  .buildStrict((List<String>) null));
    }

    @Test
    public void testBuildStrictWithNullCMK() throws Exception {
      RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);

      assertThrows(
          IllegalArgumentException.class,
          () ->
              KmsMasterKeyProvider.builder()
                  .customRegionalClientSupplier(supplier)
                  .buildStrict((String) null));

      assertThrows(
          IllegalArgumentException.class,
          () ->
              KmsMasterKeyProvider.builder()
                  .customRegionalClientSupplier(supplier)
                  .buildStrict(Arrays.asList((String) null)));
    }

    @Test
    public void testBuildDiscoveryWithFilter() throws Exception {
      RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);

      KmsMasterKeyProvider mkp1 =
          KmsMasterKeyProvider.builder()
              .customRegionalClientSupplier(supplier)
              .buildDiscovery(new DiscoveryFilter("aws", Arrays.asList("accountId")));
      assertNotNull(mkp1);
    }

    @Test
    public void testBuildDiscoveryWithNullFilter() throws Exception {
      RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);

      assertThrows(
          IllegalArgumentException.class,
          () ->
              KmsMasterKeyProvider.builder()
                  .customRegionalClientSupplier(supplier)
                  .buildDiscovery(null));
    }

    @Test
    public void testDecryptMismatchedKMSKeyIdResponse() throws Exception {
      MockKmsClient client = spy(new MockKmsClient());
      RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      DecryptResponse badResponse =
          DecryptResponse.builder()
              .keyId(KEY_ID_2)
              .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
              .build();

      doReturn(badResponse).when(client).decrypt(isA(DecryptRequest.class));

      KmsMasterKeyProvider mkp =
          KmsMasterKeyProvider.builder().customRegionalClientSupplier(supplier).buildDiscovery();

      assertThrows(
          CannotUnwrapDataKeyException.class,
          () -> mkp.decryptDataKey(ALGORITHM_SUITE, Arrays.asList(EDK_ID_1), ENCRYPTION_CONTEXT));
    }
  }
}
