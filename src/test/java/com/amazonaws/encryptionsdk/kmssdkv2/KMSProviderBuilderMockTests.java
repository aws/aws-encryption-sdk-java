// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kmssdkv2;

import static com.amazonaws.encryptionsdk.multi.MultipleProviderFactory.buildMultiProvider;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.notNull;
import static org.mockito.Mockito.*;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import java.util.Arrays;
import java.util.Optional;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.awscore.AwsRequest;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.model.CreateAliasRequest;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;

public class KMSProviderBuilderMockTests {
  @Test
  public void testBareAliasMapping() {
    MockKmsClient client = spy(new MockKmsClient());

    RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
    when(supplier.getClient(notNull())).thenReturn(client);

    String key1 = client.createKey().keyMetadata().keyId();
    client.createAlias(CreateAliasRequest.builder().aliasName("foo").targetKeyId(key1).build());

    KmsMasterKeyProvider mkp0 =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(supplier)
            .defaultRegion(Region.US_WEST_2)
            .buildStrict("alias/foo");

    AwsCrypto.standard().encryptData(mkp0, new byte[0]);
  }

  @Test
  public void testGrantTokenPassthrough_usingMKsetCall() throws Exception {
    MockKmsClient client = spy(new MockKmsClient());

    RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
    when(supplier.getClient(any())).thenReturn(client);

    String key1 = client.createKey().keyMetadata().arn();
    String key2 = client.createKey().keyMetadata().arn();

    KmsMasterKeyProvider mkp0 =
        KmsMasterKeyProvider.builder()
            .defaultRegion(Region.US_WEST_2)
            .customRegionalClientSupplier(supplier)
            .buildStrict(key1, key2);
    KmsMasterKey mk1 = mkp0.getMasterKey(key1);
    KmsMasterKey mk2 = mkp0.getMasterKey(key2);

    mk1.setGrantTokens(singletonList("foo"));
    mk2.setGrantTokens(singletonList("foo"));

    MasterKeyProvider<?> mkp = buildMultiProvider(mk1, mk2);

    byte[] ciphertext = AwsCrypto.standard().encryptData(mkp, new byte[0]).getResult();

    ArgumentCaptor<GenerateDataKeyRequest> gdkr =
        ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
    verify(client, times(1)).generateDataKey(gdkr.capture());

    assertEquals(key1, gdkr.getValue().keyId());
    assertEquals(1, gdkr.getValue().grantTokens().size());
    assertEquals("foo", gdkr.getValue().grantTokens().get(0));

    ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
    verify(client, times(1)).encrypt(er.capture());

    assertEquals(key2, er.getValue().keyId());
    assertEquals(1, er.getValue().grantTokens().size());
    assertEquals("foo", er.getValue().grantTokens().get(0));

    AwsCrypto.standard().decryptData(mkp, ciphertext);

    ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decrypt.capture());

    assertEquals(1, decrypt.getValue().grantTokens().size());
    assertEquals("foo", decrypt.getValue().grantTokens().get(0));

    verify(supplier, atLeastOnce()).getClient(Region.US_WEST_2);
    verifyNoMoreInteractions(supplier);
  }

  @Test
  public void testGrantTokenPassthrough_usingMKPWithers() throws Exception {
    MockKmsClient client = spy(new MockKmsClient());

    RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
    when(supplier.getClient(any())).thenReturn(client);

    String key1 = client.createKey().keyMetadata().arn();
    String key2 = client.createKey().keyMetadata().arn();

    KmsMasterKeyProvider mkp0 =
        KmsMasterKeyProvider.builder()
            .defaultRegion(Region.US_WEST_2)
            .customRegionalClientSupplier(supplier)
            .buildStrict(key1, key2);

    MasterKeyProvider<?> mkp = mkp0.withGrantTokens("foo");

    byte[] ciphertext = AwsCrypto.standard().encryptData(mkp, new byte[0]).getResult();

    ArgumentCaptor<GenerateDataKeyRequest> gdkr =
        ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
    verify(client, times(1)).generateDataKey(gdkr.capture());

    assertEquals(key1, gdkr.getValue().keyId());
    assertEquals(1, gdkr.getValue().grantTokens().size());
    assertEquals("foo", gdkr.getValue().grantTokens().get(0));

    ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
    verify(client, times(1)).encrypt(er.capture());

    assertEquals(key2, er.getValue().keyId());
    assertEquals(1, er.getValue().grantTokens().size());
    assertEquals("foo", er.getValue().grantTokens().get(0));

    mkp = mkp0.withGrantTokens(Arrays.asList("bar"));

    AwsCrypto.standard().decryptData(mkp, ciphertext);

    ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decrypt.capture());

    assertEquals(1, decrypt.getValue().grantTokens().size());
    assertEquals("bar", decrypt.getValue().grantTokens().get(0));

    verify(supplier, atLeastOnce()).getClient(Region.US_WEST_2);
    verifyNoMoreInteractions(supplier);
  }

  @Test
  public void testUserAgentPassthrough() throws Exception {
    MockKmsClient client = spy(new MockKmsClient());

    String key1 = client.createKey().keyMetadata().arn();
    String key2 = client.createKey().keyMetadata().arn();

    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .customRegionalClientSupplier(ignored -> client)
            .buildStrict(key1, key2);

    AwsCrypto.standard()
        .decryptData(mkp, AwsCrypto.standard().encryptData(mkp, new byte[0]).getResult());

    ArgumentCaptor<GenerateDataKeyRequest> gdkr =
        ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
    verify(client, times(1)).generateDataKey(gdkr.capture());
    assertApiName(gdkr.getValue());

    ArgumentCaptor<EncryptRequest> encr = ArgumentCaptor.forClass(EncryptRequest.class);
    verify(client, times(1)).encrypt(encr.capture());
    assertApiName(encr.getValue());

    ArgumentCaptor<DecryptRequest> decr = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decr.capture());
    assertApiName(decr.getValue());
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
