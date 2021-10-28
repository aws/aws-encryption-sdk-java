// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import static com.amazonaws.encryptionsdk.multi.MultipleProviderFactory.buildMultiProvider;
import static com.amazonaws.regions.Region.getRegion;
import static com.amazonaws.regions.Regions.fromName;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.notNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.RequestClientOptions;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider.RegionalClientSupplier;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.model.CreateAliasRequest;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

public class KMSProviderBuilderMockTests {
  @Test
  public void testBareAliasMapping() {
    MockKMSClient client = spy(new MockKMSClient());

    RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
    when(supplier.getClient(notNull())).thenReturn(client);

    String key1 = client.createKey().getKeyMetadata().getKeyId();
    client.createAlias(new CreateAliasRequest().withAliasName("foo").withTargetKeyId(key1));

    KmsMasterKeyProvider mkp0 =
        KmsMasterKeyProvider.builder()
            .withCustomClientFactory(supplier)
            .withDefaultRegion("us-west-2")
            .buildStrict("alias/foo");

    AwsCrypto.builder()
        .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
        .build()
        .encryptData(mkp0, new byte[0]);
  }

  @Test
  @SuppressWarnings("deprecation")
  public void testBareAliasMapping_withLegacyCtor() {
    MockKMSClient client = spy(new MockKMSClient());

    RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
    when(supplier.getClient(any())).thenReturn(client);

    String key1 = client.createKey().getKeyMetadata().getKeyId();
    client.createAlias(new CreateAliasRequest().withAliasName("foo").withTargetKeyId(key1));

    KmsMasterKeyProvider mkp0 =
        new KmsMasterKeyProvider(
            client, Region.getRegion(Regions.DEFAULT_REGION), Arrays.asList("alias/foo"));

    AwsCrypto.builder()
        .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
        .build()
        .encryptData(mkp0, new byte[0]);
  }

  @Test
  public void testGrantTokenPassthrough_usingMKsetCall() throws Exception {
    MockKMSClient client = spy(new MockKMSClient());

    RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
    when(supplier.getClient(any())).thenReturn(client);

    String key1 = client.createKey().getKeyMetadata().getArn();
    String key2 = client.createKey().getKeyMetadata().getArn();

    KmsMasterKeyProvider mkp0 =
        KmsMasterKeyProvider.builder()
            .withDefaultRegion("us-west-2")
            .withCustomClientFactory(supplier)
            .buildStrict(key1, key2);
    KmsMasterKey mk1 = mkp0.getMasterKey(key1);
    KmsMasterKey mk2 = mkp0.getMasterKey(key2);

    mk1.setGrantTokens(singletonList("foo"));
    mk2.setGrantTokens(singletonList("foo"));

    MasterKeyProvider<?> mkp = buildMultiProvider(mk1, mk2);

    byte[] ciphertext =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build()
            .encryptData(mkp, new byte[0])
            .getResult();

    ArgumentCaptor<GenerateDataKeyRequest> gdkr =
        ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
    verify(client, times(1)).generateDataKey(gdkr.capture());

    assertEquals(key1, gdkr.getValue().getKeyId());
    assertEquals(1, gdkr.getValue().getGrantTokens().size());
    assertEquals("foo", gdkr.getValue().getGrantTokens().get(0));

    ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
    verify(client, times(1)).encrypt(er.capture());

    assertEquals(key2, er.getValue().getKeyId());
    assertEquals(1, er.getValue().getGrantTokens().size());
    assertEquals("foo", er.getValue().getGrantTokens().get(0));

    AwsCrypto.builder()
        .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
        .build()
        .decryptData(mkp, ciphertext);

    ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decrypt.capture());

    assertEquals(1, decrypt.getValue().getGrantTokens().size());
    assertEquals("foo", decrypt.getValue().getGrantTokens().get(0));

    verify(supplier, atLeastOnce()).getClient("us-west-2");
    verifyNoMoreInteractions(supplier);
  }

  @Test
  public void testGrantTokenPassthrough_usingMKPWithers() throws Exception {
    MockKMSClient client = spy(new MockKMSClient());

    RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
    when(supplier.getClient(any())).thenReturn(client);

    String key1 = client.createKey().getKeyMetadata().getArn();
    String key2 = client.createKey().getKeyMetadata().getArn();

    KmsMasterKeyProvider mkp0 =
        KmsMasterKeyProvider.builder()
            .withDefaultRegion("us-west-2")
            .withCustomClientFactory(supplier)
            .buildStrict(key1, key2);

    MasterKeyProvider<?> mkp = mkp0.withGrantTokens("foo");

    byte[] ciphertext =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build()
            .encryptData(mkp, new byte[0])
            .getResult();

    ArgumentCaptor<GenerateDataKeyRequest> gdkr =
        ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
    verify(client, times(1)).generateDataKey(gdkr.capture());

    assertEquals(key1, gdkr.getValue().getKeyId());
    assertEquals(1, gdkr.getValue().getGrantTokens().size());
    assertEquals("foo", gdkr.getValue().getGrantTokens().get(0));

    ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
    verify(client, times(1)).encrypt(er.capture());

    assertEquals(key2, er.getValue().getKeyId());
    assertEquals(1, er.getValue().getGrantTokens().size());
    assertEquals("foo", er.getValue().getGrantTokens().get(0));

    mkp = mkp0.withGrantTokens(Arrays.asList("bar"));

    AwsCrypto.builder()
        .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
        .build()
        .decryptData(mkp, ciphertext);

    ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decrypt.capture());

    assertEquals(1, decrypt.getValue().getGrantTokens().size());
    assertEquals("bar", decrypt.getValue().getGrantTokens().get(0));

    verify(supplier, atLeastOnce()).getClient("us-west-2");
    verifyNoMoreInteractions(supplier);
  }

  @Test
  @SuppressWarnings("deprecation")
  public void testLegacyGrantTokenPassthrough() throws Exception {
    MockKMSClient client = spy(new MockKMSClient());

    String key1 = client.createKey().getKeyMetadata().getArn();

    KmsMasterKeyProvider mkp =
        new KmsMasterKeyProvider(client, getRegion(fromName("us-west-2")), singletonList(key1));

    mkp.addGrantToken("x");
    mkp.setGrantTokens(new ArrayList<>(Arrays.asList("y")));
    mkp.setGrantTokens(new ArrayList<>(Arrays.asList("a", "b")));
    mkp.addGrantToken("c");

    byte[] ciphertext =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build()
            .encryptData(mkp, new byte[0])
            .getResult();

    ArgumentCaptor<GenerateDataKeyRequest> gdkr =
        ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
    verify(client, times(1)).generateDataKey(gdkr.capture());

    List<String> grantTokens = gdkr.getValue().getGrantTokens();
    assertTrue(grantTokens.contains("a"));
    assertTrue(grantTokens.contains("b"));
    assertTrue(grantTokens.contains("c"));
    assertFalse(grantTokens.contains("x"));
    assertFalse(grantTokens.contains("z"));
  }

  @Test
  public void testUserAgentPassthrough() throws Exception {
    MockKMSClient client = spy(new MockKMSClient());

    String key1 = client.createKey().getKeyMetadata().getArn();
    String key2 = client.createKey().getKeyMetadata().getArn();

    KmsMasterKeyProvider mkp =
        KmsMasterKeyProvider.builder()
            .withCustomClientFactory(ignored -> client)
            .buildStrict(key1, key2);

    AwsCrypto.builder()
        .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
        .build()
        .decryptData(
            mkp,
            AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
                .build()
                .encryptData(mkp, new byte[0])
                .getResult());

    ArgumentCaptor<GenerateDataKeyRequest> gdkr =
        ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
    verify(client, times(1)).generateDataKey(gdkr.capture());
    assertTrue(getUA(gdkr.getValue()).contains(VersionInfo.USER_AGENT));

    ArgumentCaptor<EncryptRequest> encr = ArgumentCaptor.forClass(EncryptRequest.class);
    verify(client, times(1)).encrypt(encr.capture());
    assertTrue(getUA(encr.getValue()).contains(VersionInfo.USER_AGENT));

    ArgumentCaptor<DecryptRequest> decr = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(client, times(1)).decrypt(decr.capture());
    assertTrue(getUA(decr.getValue()).contains(VersionInfo.USER_AGENT));
  }

  private String getUA(AmazonWebServiceRequest request) {
    // Note: This test may break in future versions of the AWS SDK, as Marker is documented as being
    // for internal
    // use only.
    return request
        .getRequestClientOptions()
        .getClientMarker(RequestClientOptions.Marker.USER_AGENT);
  }
}
