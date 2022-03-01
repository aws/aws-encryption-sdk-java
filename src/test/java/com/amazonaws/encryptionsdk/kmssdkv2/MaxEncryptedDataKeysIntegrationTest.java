// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kmssdkv2;

import static org.junit.Assert.assertArrayEquals;
import static org.mockito.Mockito.*;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import java.util.ArrayList;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;

public class MaxEncryptedDataKeysIntegrationTest {
  private static final byte[] PLAINTEXT = {1, 2, 3, 4};
  private static final int MAX_EDKS = 3;

  private KmsClient testClient_;
  private RegionalClientSupplier testClientSupplier_;
  private AwsCrypto testCryptoClient_;

  @Before
  public void setup() {
    testClient_ = spy(new ProxyKmsClient(KmsClient.builder().region(Region.US_WEST_2).build()));
    testClientSupplier_ =
        region -> {
          if (region == Region.US_WEST_2) {
            return testClient_;
          }
          throw new AwsCryptoException(
              "test supplier only configured for us-west-2 and eu-central-1");
        };
    testCryptoClient_ = AwsCrypto.standard().toBuilder().withMaxEncryptedDataKeys(MAX_EDKS).build();
  }

  private KmsMasterKeyProvider providerWithEdks(int numKeys) {
    List<String> keyIds = new ArrayList<>(numKeys);
    for (int i = 0; i < numKeys; i++) {
      keyIds.add(KMSTestFixtures.US_WEST_2_KEY_ID);
    }
    return KmsMasterKeyProvider.builder()
        .customRegionalClientSupplier(testClientSupplier_)
        .buildStrict(keyIds);
  }

  @Test
  public void encryptDecryptWithLessThanMaxEdks() {
    KmsMasterKeyProvider provider = providerWithEdks(MAX_EDKS - 1);
    byte[] ciphertext = testCryptoClient_.encryptData(provider, PLAINTEXT).getResult();
    byte[] decrypted = testCryptoClient_.decryptData(provider, ciphertext).getResult();
    assertArrayEquals(decrypted, PLAINTEXT);
  }

  @Test
  public void encryptDecryptWithMaxEdks() {
    KmsMasterKeyProvider provider = providerWithEdks(MAX_EDKS);
    byte[] ciphertext = testCryptoClient_.encryptData(provider, PLAINTEXT).getResult();
    byte[] decrypted = testCryptoClient_.decryptData(provider, ciphertext).getResult();
    assertArrayEquals(decrypted, PLAINTEXT);
  }

  @Test
  public void noEncryptWithMoreThanMaxEdks() {
    KmsMasterKeyProvider provider = providerWithEdks(MAX_EDKS + 1);
    TestUtils.assertThrows(
        AwsCryptoException.class,
        "Encrypted data keys exceed maxEncryptedDataKeys",
        () -> testCryptoClient_.encryptData(provider, PLAINTEXT));
  }

  @Test
  public void noDecryptWithMoreThanMaxEdks() {
    KmsMasterKeyProvider provider = providerWithEdks(MAX_EDKS + 1);
    byte[] ciphertext = AwsCrypto.standard().encryptData(provider, PLAINTEXT).getResult();
    TestUtils.assertThrows(
        AwsCryptoException.class,
        "Ciphertext encrypted data keys exceed maxEncryptedDataKeys",
        () -> testCryptoClient_.decryptData(provider, ciphertext));
    verify(testClient_, never()).decrypt((DecryptRequest) any());
  }
}
