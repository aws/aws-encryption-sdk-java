// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.RequestClientOptions;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

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
    AWSKMS client = spy(new MockKMSClient());
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
    String keyId = client.createKey().getKeyMetadata().getArn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);
    kmsMasterKey.setGrantTokens(GRANT_TOKENS);

    DataKey<KmsMasterKey> encryptDataKeyResult =
        kmsMasterKey.encryptDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT, dataKey);

    ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
    verify(client, times(1)).encrypt(er.capture());

    EncryptRequest actualRequest = er.getValue();
    assertEquals(keyId, actualRequest.getKeyId());
    assertEquals(GRANT_TOKENS, actualRequest.getGrantTokens());
    assertEquals(ENCRYPTION_CONTEXT, actualRequest.getEncryptionContext());
    assertArrayEquals(DATA_KEY.getEncoded(), actualRequest.getPlaintext().array());
    assertUserAgent(actualRequest);

    assertEquals(encryptDataKeyResult.getMasterKey(), kmsMasterKey);
    assertEquals(AWS_KMS_PROVIDER_ID, encryptDataKeyResult.getProviderId());
    assertArrayEquals(
        keyId.getBytes(StandardCharsets.UTF_8), encryptDataKeyResult.getProviderInformation());
    assertNotNull(encryptDataKeyResult.getEncryptedDataKey());

    DataKey<KmsMasterKey> decryptDataKeyResult =
        kmsMasterKey.decryptDataKey(
            ALGORITHM_SUITE, Collections.singletonList(encryptDataKeyResult), ENCRYPTION_CONTEXT);

    ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decrypt.capture());

    DecryptRequest actualDecryptRequest = decrypt.getValue();
    assertArrayEquals(
        encryptDataKeyResult.getProviderInformation(),
        actualDecryptRequest.getKeyId().getBytes(StandardCharsets.UTF_8));
    assertEquals(GRANT_TOKENS, actualDecryptRequest.getGrantTokens());
    assertEquals(ENCRYPTION_CONTEXT, actualDecryptRequest.getEncryptionContext());
    assertArrayEquals(
        encryptDataKeyResult.getEncryptedDataKey(),
        actualDecryptRequest.getCiphertextBlob().array());
    assertUserAgent(actualDecryptRequest);

    assertEquals(DATA_KEY, decryptDataKeyResult.getKey());
    assertArrayEquals(
        keyId.getBytes(StandardCharsets.UTF_8), decryptDataKeyResult.getProviderInformation());
  }

  @Test
  public void testGenerateAndDecrypt() {
    AWSKMS client = spy(new MockKMSClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().getKeyMetadata().getArn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);
    kmsMasterKey.setGrantTokens(GRANT_TOKENS);

    DataKey<KmsMasterKey> generateDataKeyResult =
        kmsMasterKey.generateDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT);

    ArgumentCaptor<GenerateDataKeyRequest> gr =
        ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
    verify(client, times(1)).generateDataKey(gr.capture());

    GenerateDataKeyRequest actualRequest = gr.getValue();

    assertEquals(keyId, actualRequest.getKeyId());
    assertEquals(GRANT_TOKENS, actualRequest.getGrantTokens());
    assertEquals(ENCRYPTION_CONTEXT, actualRequest.getEncryptionContext());
    assertEquals(ALGORITHM_SUITE.getDataKeyLength(), actualRequest.getNumberOfBytes().longValue());
    assertUserAgent(actualRequest);

    assertNotNull(generateDataKeyResult.getKey());
    assertEquals(
        ALGORITHM_SUITE.getDataKeyLength(), generateDataKeyResult.getKey().getEncoded().length);
    assertEquals(ALGORITHM_SUITE.getDataKeyAlgo(), generateDataKeyResult.getKey().getAlgorithm());
    assertNotNull(generateDataKeyResult.getEncryptedDataKey());

    DataKey<KmsMasterKey> decryptDataKeyResult =
        kmsMasterKey.decryptDataKey(
            ALGORITHM_SUITE, Collections.singletonList(generateDataKeyResult), ENCRYPTION_CONTEXT);

    ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decrypt.capture());

    DecryptRequest actualDecryptRequest = decrypt.getValue();
    assertArrayEquals(
        generateDataKeyResult.getProviderInformation(),
        actualDecryptRequest.getKeyId().getBytes(StandardCharsets.UTF_8));
    assertEquals(GRANT_TOKENS, actualDecryptRequest.getGrantTokens());
    assertEquals(ENCRYPTION_CONTEXT, actualDecryptRequest.getEncryptionContext());
    assertArrayEquals(
        generateDataKeyResult.getEncryptedDataKey(),
        actualDecryptRequest.getCiphertextBlob().array());
    assertUserAgent(actualDecryptRequest);

    assertEquals(generateDataKeyResult.getKey(), decryptDataKeyResult.getKey());
    assertArrayEquals(
        keyId.getBytes(StandardCharsets.UTF_8), decryptDataKeyResult.getProviderInformation());
  }

  @Test
  public void testEncryptWithRawKeyId() {
    AWSKMS client = spy(new MockKMSClient());
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
    String keyId = client.createKey().getKeyMetadata().getArn();
    String rawKeyId = keyId.split("/")[1];
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, rawKeyId, mkp);
    kmsMasterKey.setGrantTokens(GRANT_TOKENS);

    DataKey<KmsMasterKey> encryptDataKeyResult =
        kmsMasterKey.encryptDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT, dataKey);

    ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
    verify(client, times(1)).encrypt(er.capture());

    EncryptRequest actualRequest = er.getValue();

    assertEquals(rawKeyId, actualRequest.getKeyId());
    assertEquals(GRANT_TOKENS, actualRequest.getGrantTokens());
    assertEquals(ENCRYPTION_CONTEXT, actualRequest.getEncryptionContext());
    assertArrayEquals(DATA_KEY.getEncoded(), actualRequest.getPlaintext().array());
    assertUserAgent(actualRequest);

    assertEquals(AWS_KMS_PROVIDER_ID, encryptDataKeyResult.getProviderId());
    assertArrayEquals(
        keyId.getBytes(StandardCharsets.UTF_8), encryptDataKeyResult.getProviderInformation());
    assertNotNull(encryptDataKeyResult.getEncryptedDataKey());
  }

  @Test
  public void testEncryptWrongKeyFormat() {
    SecretKey key = mock(SecretKey.class);
    when(key.getFormat()).thenReturn("BadFormat");

    AWSKMS client = spy(new MockKMSClient());
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
    String keyId = client.createKey().getKeyMetadata().getArn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    assertThrows(
        IllegalArgumentException.class,
        () -> kmsMasterKey.encryptDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT, dataKey));
  }

  @Test
  public void testGenerateBadKmsKeyLength() {
    AWSKMS client = spy(new MockKMSClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().getKeyMetadata().getArn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    GenerateDataKeyResult badResult = new GenerateDataKeyResult();
    badResult.setKeyId(keyId);
    badResult.setPlaintext(ByteBuffer.allocate(ALGORITHM_SUITE.getDataKeyLength() + 1));

    doReturn(badResult).when(client).generateDataKey(isA(GenerateDataKeyRequest.class));

    assertThrows(
        IllegalStateException.class,
        () -> kmsMasterKey.generateDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT));
  }

  @Test
  public void testDecryptBadKmsKeyLength() {
    AWSKMS client = spy(new MockKMSClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().getKeyMetadata().getArn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    DecryptResult badResult = new DecryptResult();
    badResult.setKeyId(keyId);
    badResult.setPlaintext(ByteBuffer.allocate(ALGORITHM_SUITE.getDataKeyLength() + 1));

    doReturn(badResult).when(client).decrypt(isA(DecryptRequest.class));

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
    AWSKMS client = spy(new MockKMSClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().getKeyMetadata().getArn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    DecryptResult badResult = new DecryptResult();
    badResult.setPlaintext(ByteBuffer.allocate(ALGORITHM_SUITE.getDataKeyLength()));

    doReturn(badResult).when(client).decrypt(isA(DecryptRequest.class));

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
    AWSKMS client = spy(new MockKMSClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().getKeyMetadata().getArn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    DecryptResult badResult = new DecryptResult();
    badResult.setKeyId("mismatchedID");
    badResult.setPlaintext(ByteBuffer.allocate(ALGORITHM_SUITE.getDataKeyLength()));

    doReturn(badResult).when(client).decrypt(isA(DecryptRequest.class));

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
    AWSKMS client = spy(new MockKMSClient());
    Supplier supplier = mock(Supplier.class);
    when(supplier.get()).thenReturn(client);

    MasterKeyProvider mkp = mock(MasterKeyProvider.class);
    when(mkp.getDefaultProviderId()).thenReturn(AWS_KMS_PROVIDER_ID);
    String keyId = client.createKey().getKeyMetadata().getArn();
    KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, keyId, mkp);

    // Mock expected KMS response to verify success if second EDK is ok,
    // and the mismatched EDK is skipped vs failing outright
    DecryptResult kmsResponse = new DecryptResult();
    kmsResponse.setKeyId(keyId);
    kmsResponse.setPlaintext(ByteBuffer.allocate(ALGORITHM_SUITE.getDataKeyLength()));
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

    DataKey<KmsMasterKey> decryptDataKeyResult =
        kmsMasterKey.decryptDataKey(
            ALGORITHM_SUITE, Arrays.asList(mismatchedEDK, edk), ENCRYPTION_CONTEXT);

    ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decrypt.capture());

    DecryptRequest actualDecryptRequest = decrypt.getValue();
    assertArrayEquals(
        edk.getProviderInformation(),
        actualDecryptRequest.getKeyId().getBytes(StandardCharsets.UTF_8));
  }

  private void assertUserAgent(AmazonWebServiceRequest request) {
    assertTrue(
        request
            .getRequestClientOptions()
            .getClientMarker(RequestClientOptions.Marker.USER_AGENT)
            .contains(VersionInfo.USER_AGENT));
  }
}
