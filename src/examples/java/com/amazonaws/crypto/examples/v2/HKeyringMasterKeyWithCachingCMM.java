// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.CryptoMaterialsCache;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class HKeyringMasterKeyWithCachingCMM {
  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void encryptAndDecryptWithKeyringViaCachingCMM(
      String keyStoreTableName, String logicalKeyStoreName, String kmsKeyId) {
    final AwsCrypto crypto = AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptAllowDecrypt)
            .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
            .withMaxEncryptedDataKeys(1)
            .build();

    // Configure your KeyStore resource.
    //    This SHOULD be the same configuration that you used
    //    to initially create and populate your KeyStore.
    final KeyStore keystore =
        KeyStore.builder()
            .KeyStoreConfig(
                KeyStoreConfig.builder()
                    .ddbClient(DynamoDbClient.create())
                    .ddbTableName(keyStoreTableName)
                    .logicalKeyStoreName(logicalKeyStoreName)
                    .kmsClient(KmsClient.create())
                    .kmsConfiguration(KMSConfiguration.builder().kmsKeyArn(kmsKeyId).build())
                    .build())
            .build();

    // Call CreateKey to create two new active branch keys
    final String branchKeyIdA =
        keystore.CreateKey(CreateKeyInput.builder().build()).branchKeyIdentifier();

    // 4. Create the Hierarchical Keyring.
    final MaterialProviders matProv =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateAwsKmsHierarchicalKeyringInput keyringInput =
        CreateAwsKmsHierarchicalKeyringInput.builder()
            .keyStore(keystore)
            .branchKeyId(branchKeyIdA)
            .ttlSeconds(600)
            .cache(
                CacheType.builder()
                        .MultiThreaded(MultiThreadedCache.builder().entryCapacity(100).build())// OPTIONAL
                    .build())
            .build();

    Map<String, String> encryptionContextA = new HashMap<>();
    encryptionContextA.put("tenant", "TenantA");
    HKeyringMasterKey masterKey = new HKeyringMasterKey(keyringInput);
    final IKeyring hierarchicalKeyringA = matProv.CreateAwsKmsHierarchicalKeyring(keyringInput);

    // Create a cache
    CryptoMaterialsCache cache = new LocalCryptoMaterialsCache(100);

    // Create a caching CMM
    CryptoMaterialsManager cachingCmm =
            CachingCryptoMaterialsManager.newBuilder().withMasterKeyProvider(masterKey)
                    .withCache(cache)
                    .withMaxAge(100, TimeUnit.SECONDS)
                    .withMessageUseLimit(1000)
                    .build();

    // Encrypt the data for encryptionContextA & encryptionContextB
    final CryptoResult<byte[], ?> encryptResultA =
        crypto.encryptData(cachingCmm, EXAMPLE_DATA, encryptionContextA);

    // OK. Can the Keyring decrypt it?
    CryptoResult<byte[], ?> decryptResultA =
            crypto.decryptData(hierarchicalKeyringA, encryptResultA.getResult());
    assert Arrays.equals(decryptResultA.getResult(), EXAMPLE_DATA);

    // OK. Can the Caching CMM Decrypt it?
    decryptResultA = crypto.decryptData(cachingCmm, encryptResultA.getResult());
    assert Arrays.equals(decryptResultA.getResult(), EXAMPLE_DATA);
  }

  public static void main(final String[] args) {
    if (args.length <= 0) {
      throw new IllegalArgumentException(
          "To run this example, include the keyStoreTableName, logicalKeyStoreName, and kmsKeyId in args");
    }
    final String keyStoreTableName = args[0];
    final String logicalKeyStoreName = args[1];
    final String kmsKeyId = args[2];
    encryptAndDecryptWithKeyringViaCachingCMM(keyStoreTableName, logicalKeyStoreName, kmsKeyId);
  }
}
