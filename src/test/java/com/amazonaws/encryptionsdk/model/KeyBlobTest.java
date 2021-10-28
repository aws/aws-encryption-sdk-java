/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.encryptionsdk.model;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.RandomBytesGenerator;
import com.amazonaws.encryptionsdk.internal.StaticMasterKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;

public class KeyBlobTest {
  private static CryptoAlgorithm ALGORITHM = CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_NO_KDF;
  final String providerId_ = "Test Key";
  final String providerInfo_ = "Test Info";
  private StaticMasterKey masterKeyProvider_;

  @Before
  public void init() {
    masterKeyProvider_ = new StaticMasterKey("testmaterial");
  }

  private byte[] createKeyBlobBytes() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "Test Encryption Context");
    final DataKey<StaticMasterKey> mockDataKey_ =
        masterKeyProvider_.generateDataKey(ALGORITHM, encryptionContext);

    final KeyBlob keyBlob =
        new KeyBlob(
            providerId_,
            providerInfo_.getBytes(StandardCharsets.UTF_8),
            mockDataKey_.getEncryptedDataKey());

    return keyBlob.toByteArray();
  }

  private KeyBlob deserialize(final byte[] keyBlobBytes) {
    final KeyBlob reconstructedKeyBlob = new KeyBlob();
    reconstructedKeyBlob.deserialize(keyBlobBytes, 0);
    return reconstructedKeyBlob;
  }

  @Test
  public void serializeDeserialize() {
    final byte[] keyBlobBytes = createKeyBlobBytes();

    final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);
    final byte[] reconstructedKeyBlobBytes = reconstructedKeyBlob.toByteArray();

    assertArrayEquals(reconstructedKeyBlobBytes, keyBlobBytes);
  }

  @Test(expected = AwsCryptoException.class)
  public void overlyLargeKeyProviderIdLen() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "Test Encryption Context");

    final DataKey<StaticMasterKey> mockDataKey =
        masterKeyProvider_.generateDataKey(ALGORITHM, encryptionContext);

    final int providerId_Len = Constants.UNSIGNED_SHORT_MAX_VAL + 1;
    final byte[] providerId_Bytes = RandomBytesGenerator.generate(providerId_Len);
    final String providerId_ = new String(providerId_Bytes, StandardCharsets.UTF_8);

    final String providerInfo_ = "Test Info";

    new KeyBlob(
        providerId_,
        providerInfo_.getBytes(StandardCharsets.UTF_8),
        mockDataKey.getEncryptedDataKey());
  }

  @Test(expected = AwsCryptoException.class)
  public void overlyLargeKeyProviderInfoLen() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "Test Encryption Context");

    final DataKey<StaticMasterKey> mockDataKey =
        masterKeyProvider_.generateDataKey(ALGORITHM, encryptionContext);

    final int providerInfo_Len = Constants.UNSIGNED_SHORT_MAX_VAL + 1;
    final byte[] providerInfo_ = RandomBytesGenerator.generate(providerInfo_Len);

    new KeyBlob(providerId_, providerInfo_, mockDataKey.getEncryptedDataKey());
  }

  @Test(expected = AwsCryptoException.class)
  public void overlyLargeKey() {
    final int keyLen = Constants.UNSIGNED_SHORT_MAX_VAL + 1;
    final byte[] encryptedKeyBytes = RandomBytesGenerator.generate(keyLen);

    new KeyBlob(providerId_, providerInfo_.getBytes(StandardCharsets.UTF_8), encryptedKeyBytes);
  }

  @Test
  public void deserializeNull() {
    final KeyBlob keyBlob = new KeyBlob();
    final int deserializedBytes = keyBlob.deserialize(null, 0);

    assertEquals(0, deserializedBytes);
  }

  @Test
  public void checkKeyProviderIdLen() {
    final byte[] keyBlobBytes = createKeyBlobBytes();

    final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);

    assertEquals(providerId_.length(), reconstructedKeyBlob.getKeyProviderIdLen());
  }

  @Test
  public void checkKeyProviderId() {
    final byte[] keyBlobBytes = createKeyBlobBytes();

    final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);

    assertArrayEquals(
        providerId_.getBytes(StandardCharsets.UTF_8),
        reconstructedKeyBlob.getProviderId().getBytes(StandardCharsets.UTF_8));
  }

  @Test
  public void checkKeyProviderInfoLen() {
    final byte[] keyBlobBytes = createKeyBlobBytes();

    final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);

    assertEquals(providerInfo_.length(), reconstructedKeyBlob.getKeyProviderInfoLen());
  }

  @Test
  public void checkKeyProviderInfo() {
    final byte[] keyBlobBytes = createKeyBlobBytes();

    final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);

    assertArrayEquals(
        providerInfo_.getBytes(StandardCharsets.UTF_8),
        reconstructedKeyBlob.getProviderInformation());
  }

  @Test
  public void checkKeyLen() {
    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC", "Test Encryption Context");
    final DataKey<StaticMasterKey> mockDataKey_ =
        masterKeyProvider_.generateDataKey(ALGORITHM, encryptionContext);

    final KeyBlob keyBlob =
        new KeyBlob(
            providerId_,
            providerInfo_.getBytes(StandardCharsets.UTF_8),
            mockDataKey_.getEncryptedDataKey());

    final byte[] keyBlobBytes = keyBlob.toByteArray();

    final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);

    assertEquals(
        mockDataKey_.getEncryptedDataKey().length, reconstructedKeyBlob.getEncryptedDataKeyLen());
  }

  private KeyBlob generateRandomKeyBlob(int idLen, int infoLen, int keyLen) {
    final byte[] idBytes = new byte[idLen];
    Arrays.fill(idBytes, (byte) 'A');

    final byte[] infoBytes = RandomBytesGenerator.generate(infoLen);
    final byte[] keyBytes = RandomBytesGenerator.generate(keyLen);

    return new KeyBlob(new String(idBytes, StandardCharsets.UTF_8), infoBytes, keyBytes);
  }

  private void assertKeyBlobsEqual(KeyBlob b1, KeyBlob b2) {
    assertArrayEquals(
        b1.getProviderId().getBytes(StandardCharsets.UTF_8),
        b2.getProviderId().getBytes(StandardCharsets.UTF_8));
    assertArrayEquals(b1.getProviderInformation(), b2.getProviderInformation());
    assertArrayEquals(b1.getEncryptedDataKey(), b2.getEncryptedDataKey());
  }

  @Test
  public void checkKeyProviderIdLenUnsigned() {
    // provider id length is too large for a signed short but fits in unsigned
    final KeyBlob blob =
        generateRandomKeyBlob(Constants.UNSIGNED_SHORT_MAX_VAL, Short.MAX_VALUE, Short.MAX_VALUE);
    final byte[] arr = blob.toByteArray();

    assertKeyBlobsEqual(deserialize(arr), blob);
  }

  @Test
  public void checkKeyProviderInfoLenUnsigned() {
    // provider info length is too large for a signed short but fits in unsigned
    final KeyBlob blob =
        generateRandomKeyBlob(Short.MAX_VALUE, Constants.UNSIGNED_SHORT_MAX_VAL, Short.MAX_VALUE);
    final byte[] arr = blob.toByteArray();

    assertKeyBlobsEqual(deserialize(arr), blob);
  }

  @Test
  public void checkKeyLenUnsigned() {
    // key length is too large for a signed short but fits in unsigned
    final KeyBlob blob =
        generateRandomKeyBlob(Short.MAX_VALUE, Short.MAX_VALUE, Constants.UNSIGNED_SHORT_MAX_VAL);
    final byte[] arr = blob.toByteArray();

    assertKeyBlobsEqual(deserialize(arr), blob);
  }
}
