// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kmssdkv2;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Supplier;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.awscore.AwsRequest;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

public class KmsMasterKeyTest {

  private static final String AWS_KMS_PROVIDER_ID = "aws-kms";
  private static final String OTHER_PROVIDER_ID = "not-aws-kms";

  private static final CryptoAlgorithm ALGORITHM_SUITE =
      CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
  private static final SecretKey DATA_KEY =
      new SecretKeySpec(
          generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());
  private static final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
  private static final Map<String, String> ENCRYPTION_CONTEXT =
      Collections.singletonMap("myKey", "myValue");

  @Test
  public void testEncryptAndDecrypt() {
    KmsClient client = spy(new MockKmsClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKey otherMasterKey = mock(MasterKey.class);
    when(otherMasterKey.getProviderId()).thenReturn(OTHER_PROVIDER_ID);
    when(otherMasterKey.getKeyId()).thenReturn("someOtherId");
    DataKey dataKey =
        new DataKey(
            DATA_KEY,
            new byte[0],
            OTHER_PROVIDER_ID.getBytes(StandardCharsets.UTF_8),
            otherMasterKey);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().keyMetadata().arn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);
    kmsMasterKey.setGrantTokens(GRANT_TOKENS);

    DataKey<KmsMasterKey> encryptDataKeyResponse =
        kmsMasterKey.encryptDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT, dataKey);

    ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
    verify(client, times(1)).encrypt(er.capture());

    EncryptRequest actualRequest = er.getValue();
    assertEquals(keyId, actualRequest.keyId());
    assertEquals(GRANT_TOKENS, actualRequest.grantTokens());
    assertEquals(ENCRYPTION_CONTEXT, actualRequest.encryptionContext());
    assertArrayEquals(DATA_KEY.getEncoded(), actualRequest.plaintext().asByteArray());
    assertApiName(actualRequest);

    assertEquals(encryptDataKeyResponse.getMasterKey(), kmsMasterKey);
    assertEquals(AWS_KMS_PROVIDER_ID, encryptDataKeyResponse.getProviderId());
    assertArrayEquals(
        keyId.getBytes(StandardCharsets.UTF_8), encryptDataKeyResponse.getProviderInformation());
    assertNotNull(encryptDataKeyResponse.getEncryptedDataKey());

    DataKey<KmsMasterKey> decryptDataKeyResponse =
        kmsMasterKey.decryptDataKey(
            ALGORITHM_SUITE, Collections.singletonList(encryptDataKeyResponse), ENCRYPTION_CONTEXT);

    ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decrypt.capture());

    DecryptRequest actualDecryptRequest = decrypt.getValue();
    assertArrayEquals(
        encryptDataKeyResponse.getProviderInformation(),
        actualDecryptRequest.keyId().getBytes(StandardCharsets.UTF_8));
    assertEquals(GRANT_TOKENS, actualDecryptRequest.grantTokens());
    assertEquals(ENCRYPTION_CONTEXT, actualDecryptRequest.encryptionContext());
    assertArrayEquals(
        encryptDataKeyResponse.getEncryptedDataKey(),
        actualDecryptRequest.ciphertextBlob().asByteArray());
    assertApiName(actualDecryptRequest);

    assertEquals(DATA_KEY, decryptDataKeyResponse.getKey());
    assertArrayEquals(
        keyId.getBytes(StandardCharsets.UTF_8), decryptDataKeyResponse.getProviderInformation());
  }

  @Test
  public void testGenerateAndDecrypt() {
    KmsClient client = spy(new MockKmsClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().keyMetadata().arn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);
    kmsMasterKey.setGrantTokens(GRANT_TOKENS);

    DataKey<KmsMasterKey> generateDataKeyResponse =
        kmsMasterKey.generateDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT);

    ArgumentCaptor<GenerateDataKeyRequest> gr =
        ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
    verify(client, times(1)).generateDataKey(gr.capture());

    GenerateDataKeyRequest actualRequest = gr.getValue();

    assertEquals(keyId, actualRequest.keyId());
    assertEquals(GRANT_TOKENS, actualRequest.grantTokens());
    assertEquals(ENCRYPTION_CONTEXT, actualRequest.encryptionContext());
    assertEquals(ALGORITHM_SUITE.getDataKeyLength(), actualRequest.numberOfBytes().longValue());
    assertApiName(actualRequest);

    assertNotNull(generateDataKeyResponse.getKey());
    assertEquals(
        ALGORITHM_SUITE.getDataKeyLength(), generateDataKeyResponse.getKey().getEncoded().length);
    assertEquals(ALGORITHM_SUITE.getDataKeyAlgo(), generateDataKeyResponse.getKey().getAlgorithm());
    assertNotNull(generateDataKeyResponse.getEncryptedDataKey());

    DataKey<KmsMasterKey> decryptDataKeyResponse =
        kmsMasterKey.decryptDataKey(
            ALGORITHM_SUITE,
            Collections.singletonList(generateDataKeyResponse),
            ENCRYPTION_CONTEXT);

    ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decrypt.capture());

    DecryptRequest actualDecryptRequest = decrypt.getValue();
    assertArrayEquals(
        generateDataKeyResponse.getProviderInformation(),
        actualDecryptRequest.keyId().getBytes(StandardCharsets.UTF_8));
    assertEquals(GRANT_TOKENS, actualDecryptRequest.grantTokens());
    assertEquals(ENCRYPTION_CONTEXT, actualDecryptRequest.encryptionContext());
    assertArrayEquals(
        generateDataKeyResponse.getEncryptedDataKey(),
        actualDecryptRequest.ciphertextBlob().asByteArray());
    assertApiName(actualDecryptRequest);

    assertEquals(generateDataKeyResponse.getKey(), decryptDataKeyResponse.getKey());
    assertArrayEquals(
        keyId.getBytes(StandardCharsets.UTF_8), decryptDataKeyResponse.getProviderInformation());
  }

  @Test
  public void testEncryptWithRawKeyId() {
    KmsClient client = spy(new MockKmsClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKey otherMasterKey = mock(MasterKey.class);
    when(otherMasterKey.getProviderId()).thenReturn(OTHER_PROVIDER_ID);
    when(otherMasterKey.getKeyId()).thenReturn("someOtherId");
    DataKey dataKey =
        new DataKey(
            DATA_KEY,
            new byte[0],
            OTHER_PROVIDER_ID.getBytes(StandardCharsets.UTF_8),
            otherMasterKey);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().keyMetadata().arn();
    String rawKeyId = keyId.split("/")[1];
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, rawKeyId, mkp);
    kmsMasterKey.setGrantTokens(GRANT_TOKENS);

    DataKey<KmsMasterKey> encryptDataKeyResponse =
        kmsMasterKey.encryptDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT, dataKey);

    ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
    verify(client, times(1)).encrypt(er.capture());

    EncryptRequest actualRequest = er.getValue();

    assertEquals(rawKeyId, actualRequest.keyId());
    assertEquals(GRANT_TOKENS, actualRequest.grantTokens());
    assertEquals(ENCRYPTION_CONTEXT, actualRequest.encryptionContext());
    assertArrayEquals(DATA_KEY.getEncoded(), actualRequest.plaintext().asByteArray());
    assertApiName(actualRequest);

    assertEquals(AWS_KMS_PROVIDER_ID, encryptDataKeyResponse.getProviderId());
    assertArrayEquals(
        keyId.getBytes(StandardCharsets.UTF_8), encryptDataKeyResponse.getProviderInformation());
    assertNotNull(encryptDataKeyResponse.getEncryptedDataKey());
  }

  @Test
  public void testEncryptWrongKeyFormat() {
    SecretKey key = mock(SecretKey.class);
    when(key.getFormat()).thenReturn("BadFormat");

    KmsClient client = spy(new MockKmsClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKey otherMasterKey = mock(MasterKey.class);
    when(otherMasterKey.getProviderId()).thenReturn(OTHER_PROVIDER_ID);
    when(otherMasterKey.getKeyId()).thenReturn("someOtherId");
    DataKey dataKey =
        new DataKey(
            key, new byte[0], OTHER_PROVIDER_ID.getBytes(StandardCharsets.UTF_8), otherMasterKey);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().keyMetadata().arn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    assertThrows(
        IllegalArgumentException.class,
        () -> kmsMasterKey.encryptDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT, dataKey));
  }

  @Test
  public void testGenerateBadKmsKeyLength() {
    KmsClient client = spy(new MockKmsClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().keyMetadata().arn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    GenerateDataKeyResponse badResponse =
        GenerateDataKeyResponse.builder()
            .keyId(keyId)
            .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength() + 1]))
            .build();

    doReturn(badResponse).when(client).generateDataKey(isA(GenerateDataKeyRequest.class));

    assertThrows(
        IllegalStateException.class,
        () -> kmsMasterKey.generateDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT));
  }

  @Test
  public void testDecryptBadKmsKeyLength() {
    KmsClient client = spy(new MockKmsClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().keyMetadata().arn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    DecryptResponse badResponse =
        DecryptResponse.builder()
            .keyId(keyId)
            .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength() + 1]))
            .build();

    doReturn(badResponse).when(client).decrypt(isA(DecryptRequest.class));

    EncryptedDataKey edk =
        new KeyBlob(
            AWS_KMS_PROVIDER_ID,
            keyId.getBytes(StandardCharsets.UTF_8),
            generate(ALGORITHM_SUITE.getDataKeyLength()));

    assertThrows(
        IllegalStateException.class,
        () ->
            kmsMasterKey.decryptDataKey(
                ALGORITHM_SUITE, Collections.singletonList(edk), ENCRYPTION_CONTEXT));
  }

  @Test
  public void testDecryptMissingKmsKeyId() {
    KmsClient client = spy(new MockKmsClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().keyMetadata().arn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    DecryptResponse badResponse =
        DecryptResponse.builder()
            .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
            .build();

    doReturn(badResponse).when(client).decrypt(isA(DecryptRequest.class));

    EncryptedDataKey edk =
        new KeyBlob(
            AWS_KMS_PROVIDER_ID,
            keyId.getBytes(StandardCharsets.UTF_8),
            generate(ALGORITHM_SUITE.getDataKeyLength()));

    assertThrows(
        IllegalStateException.class,
        "Received an empty keyId from KMS",
        () ->
            kmsMasterKey.decryptDataKey(
                ALGORITHM_SUITE, Collections.singletonList(edk), ENCRYPTION_CONTEXT));
  }

  @Test
  public void testDecryptMismatchedKmsKeyId() {
    KmsClient client = spy(new MockKmsClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().keyMetadata().arn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    DecryptResponse badResponse =
        DecryptResponse.builder()
            .keyId("mismatchedID")
            .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
            .build();

    doReturn(badResponse).when(client).decrypt(isA(DecryptRequest.class));

    EncryptedDataKey edk =
        new KeyBlob(
            AWS_KMS_PROVIDER_ID,
            keyId.getBytes(StandardCharsets.UTF_8),
            generate(ALGORITHM_SUITE.getDataKeyLength()));

    assertThrows(
        CannotUnwrapDataKeyException.class,
        () ->
            kmsMasterKey.decryptDataKey(
                ALGORITHM_SUITE, Collections.singletonList(edk), ENCRYPTION_CONTEXT));
  }

  @Test
  public void testDecryptSkipsMismatchedIdEDK() {
    KmsClient client = spy(new MockKmsClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().keyMetadata().arn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    // Mock expected KMS response to verify success if second EDK is ok,
    // and the mismatched EDK is skipped vs failing outright
    DecryptResponse kmsResponse =
        DecryptResponse.builder()
            .keyId(keyId)
            .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
            .build();
    doReturn(kmsResponse).when(client).decrypt(isA(DecryptRequest.class));

    EncryptedDataKey edk =
        new KeyBlob(
            AWS_KMS_PROVIDER_ID,
            keyId.getBytes(StandardCharsets.UTF_8),
            generate(ALGORITHM_SUITE.getDataKeyLength()));
    EncryptedDataKey mismatchedEDK =
        new KeyBlob(
            AWS_KMS_PROVIDER_ID,
            "mismatchedID".getBytes(StandardCharsets.UTF_8),
            generate(ALGORITHM_SUITE.getDataKeyLength()));

    DataKey<KmsMasterKey> decryptDataKeyResponse =
        kmsMasterKey.decryptDataKey(
            ALGORITHM_SUITE, Arrays.asList(mismatchedEDK, edk), ENCRYPTION_CONTEXT);

    ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decrypt.capture());

    DecryptRequest actualDecryptRequest = decrypt.getValue();
    assertArrayEquals(
        edk.getProviderInformation(),
        actualDecryptRequest.keyId().getBytes(StandardCharsets.UTF_8));
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
