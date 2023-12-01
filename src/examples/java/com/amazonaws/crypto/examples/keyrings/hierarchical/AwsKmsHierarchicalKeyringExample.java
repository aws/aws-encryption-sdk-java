// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings.hierarchical;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.materialproviders.IBranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CacheType;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.DefaultCache;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This example sets up the Hierarchical Keyring, which establishes a key hierarchy where "branch"
 * keys are persisted in DynamoDb. These branch keys are used to protect your data keys, and these
 * branch keys are themselves protected by a KMS Key.
 *
 * <p>Establishing a key hierarchy like this has two benefits:
 *
 * <p>First, by caching the branch key material, and only calling KMS to re-establish authentication
 * regularly according to your configured TTL, you limit how often you need to call KMS to protect
 * your data. This is a performance security tradeoff, where your authentication, audit, and logging
 * from KMS is no longer one-to-one with every encrypt or decrypt call. Additionally, KMS Cloudtrail
 * cannot be used to distinguish Encrypt and Decrypt calls, and you cannot restrict who has
 * Encryption rights from who has Decryption rights since they both ONLY need KMS:Decrypt. However,
 * the benefit is that you no longer have to make a network call to KMS for every encrypt or
 * decrypt.
 *
 * <p>Second, this key hierarchy facilitates cryptographic isolation of a tenant's data in a
 * multi-tenant data store. Each tenant can have a unique Branch Key, that is only used to protect
 * the tenant's data. You can either statically configure a single branch key to ensure you are
 * restricting access to a single tenant, or you can implement an interface that selects the Branch
 * Key based on the Encryption Context.
 *
 * <p>This example demonstrates configuring a Hierarchical Keyring with a Branch Key ID Supplier to
 * encrypt and decrypt data for two separate tenants.
 *
 * <p>This example requires access to the DDB Table where you are storing the Branch Keys. This
 * table must be configured with the following primary key configuration: - Partition key is named
 * "partition_key" with type (S) - Sort key is named "sort_key" with type (S)
 *
 * <p>This example also requires using a KMS Key. You need the following access on this key: -
 * GenerateDataKeyWithoutPlaintext - Decrypt
 */
public class AwsKmsHierarchicalKeyringExample {
  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void encryptAndDecryptWithKeyring(
      String keyStoreTableName, String logicalKeyStoreName, String kmsKeyId) {
    // Instantiate the SDK
    // This builds the AwsCrypto client with the RequireEncryptRequireDecrypt commitment policy,
    // which enforces that this client only encrypts using committing algorithm suites and enforces
    // that this client will only decrypt encrypted messages that were created with a committing
    // algorithm suite.
    // This is the default commitment policy if you build the client with
    // `AwsCrypto.builder().build()`
    // or `AwsCrypto.standard()`.
    final AwsCrypto crypto = AwsCrypto.builder().build();

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
    final String branchKeyIdB =
        keystore.CreateKey(CreateKeyInput.builder().build()).branchKeyIdentifier();

    // Create a branch key supplier that maps the branch key id to a more readable format
    final IBranchKeyIdSupplier branchKeyIdSupplier =
        new ExampleBranchKeyIdSupplier(branchKeyIdA, branchKeyIdB);

    // 4. Create the Hierarchical Keyring.
    final MaterialProviders matProv =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateAwsKmsHierarchicalKeyringInput keyringInput =
        CreateAwsKmsHierarchicalKeyringInput.builder()
            .keyStore(keystore)
            .branchKeyIdSupplier(branchKeyIdSupplier)
            .ttlSeconds(600)
            .cache(
                CacheType.builder() // OPTIONAL
                    .Default(DefaultCache.builder().entryCapacity(100).build())
                    .build())
            .build();
    final IKeyring hierarchicalKeyring = matProv.CreateAwsKmsHierarchicalKeyring(keyringInput);

    // The Branch Key Id supplier uses the encryption context to determine which branch key id will
    // be used to encrypt data.
    // Create encryption context for TenantA
    Map<String, String> encryptionContextA = new HashMap<>();
    encryptionContextA.put("tenant", "TenantA");
    encryptionContextA.put("encryption", "context");
    encryptionContextA.put("is not", "secret");
    encryptionContextA.put("but adds", "useful metadata");
    encryptionContextA.put("that can help you", "be confident that");
    encryptionContextA.put("the data you are handling", "is what you think it is");

    // Create encryption context for TenantB
    Map<String, String> encryptionContextB = new HashMap<>();
    encryptionContextB.put("tenant", "TenantB");
    encryptionContextB.put("encryption", "context");
    encryptionContextB.put("is not", "secret");
    encryptionContextB.put("but adds", "useful metadata");
    encryptionContextB.put("that can help you", "be confident that");
    encryptionContextB.put("the data you are handling", "is what you think it is");

    // Encrypt the data for encryptionContextA & encryptionContextB
    final CryptoResult<byte[], ?> encryptResultA =
        crypto.encryptData(hierarchicalKeyring, EXAMPLE_DATA, encryptionContextA);
    final CryptoResult<byte[], ?> encryptResultB =
        crypto.encryptData(hierarchicalKeyring, EXAMPLE_DATA, encryptionContextB);

    // To attest that TenantKeyB cannot decrypt a message written by TenantKeyA
    // let's construct more restrictive hierarchical keyrings.
    final CreateAwsKmsHierarchicalKeyringInput keyringInputA =
        CreateAwsKmsHierarchicalKeyringInput.builder()
            .keyStore(keystore)
            .branchKeyId(branchKeyIdA)
            .ttlSeconds(600)
            .cache(
                CacheType.builder() // OPTIONAL
                    .Default(DefaultCache.builder().entryCapacity(100).build())
                    .build())
            .build();
    final IKeyring hierarchicalKeyringA = matProv.CreateAwsKmsHierarchicalKeyring(keyringInputA);

    final CreateAwsKmsHierarchicalKeyringInput keyringInputB =
        CreateAwsKmsHierarchicalKeyringInput.builder()
            .keyStore(keystore)
            .branchKeyId(branchKeyIdB)
            .ttlSeconds(600)
            .cache(
                CacheType.builder() // OPTIONAL
                    .Default(DefaultCache.builder().entryCapacity(100).build())
                    .build())
            .build();
    final IKeyring hierarchicalKeyringB = matProv.CreateAwsKmsHierarchicalKeyring(keyringInputB);

    boolean decryptFailed = false;
    // Try to use keyring for Tenant B to decrypt a message encrypted with Tenant A's key
    // Expected to fail.
    try {
      crypto.decryptData(hierarchicalKeyringB, encryptResultA.getResult());
    } catch (Exception e) {
      decryptFailed = true;
    }
    assert decryptFailed == true;

    decryptFailed = false;
    // Try to use keyring for Tenant A to decrypt a message encrypted with Tenant B's key
    // Expected to fail.
    try {
      crypto.decryptData(hierarchicalKeyringA, encryptResultB.getResult());
    } catch (Exception e) {
      decryptFailed = true;
    }
    assert decryptFailed == true;

    // Decrypt your encrypted data using the same keyring you used on encrypt.
    final CryptoResult<byte[], ?> decryptResultA =
        crypto.decryptData(hierarchicalKeyring, encryptResultA.getResult());
    assert Arrays.equals(decryptResultA.getResult(), EXAMPLE_DATA);

    final CryptoResult<byte[], ?> decryptResultB =
        crypto.decryptData(hierarchicalKeyring, encryptResultB.getResult());
    assert Arrays.equals(decryptResultB.getResult(), EXAMPLE_DATA);
  }

  public static void encryptAndDecryptWithKeyringThreadSafe(
      String keyStoreTableName, String logicalKeyStoreName, String kmsKeyId) {
    // Instantiate the SDK
    // This builds the AwsCrypto client with the RequireEncryptRequireDecrypt commitment policy,
    // which enforces that this client only encrypts using committing algorithm suites and enforces
    // that this client will only decrypt encrypted messages that were created with a committing
    // algorithm suite.
    // This is the default commitment policy if you build the client with
    // `AwsCrypto.builder().build()`
    // or `AwsCrypto.standard()`.
    final AwsCrypto crypto = AwsCrypto.builder().build();

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
    final String branchKeyIdB =
        keystore.CreateKey(CreateKeyInput.builder().build()).branchKeyIdentifier();

    // Create a branch key supplier that maps the branch key id to a more readable format
    final IBranchKeyIdSupplier branchKeyIdSupplier =
        new ExampleBranchKeyIdSupplier(branchKeyIdA, branchKeyIdB);

    // 4. Create the Hierarchical Keyring.
    final MaterialProviders matProv =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();

    final CreateAwsKmsHierarchicalKeyringInput keyringInput =
        CreateAwsKmsHierarchicalKeyringInput.builder()
            .keyStore(keystore)
            .branchKeyIdSupplier(branchKeyIdSupplier)
            .ttlSeconds(600)
            .cache(
                CacheType.builder() // OPTIONAL
                    .Default(DefaultCache.builder().entryCapacity(100).build())
                    .build())
            .build();
    final IKeyring hierarchicalKeyring = matProv.CreateAwsKmsHierarchicalKeyring(keyringInput);

    // The Branch Key Id supplier uses the encryption context to determine which branch key id will
    // be used to encrypt data.
    // Create encryption context for TenantA
    Map<String, String> encryptionContextA = new HashMap<>();
    encryptionContextA.put("tenant", "TenantA");
    encryptionContextA.put("encryption", "context");
    encryptionContextA.put("is not", "secret");
    encryptionContextA.put("but adds", "useful metadata");
    encryptionContextA.put("that can help you", "be confident that");
    encryptionContextA.put("the data you are handling", "is what you think it is");

    // Create encryption context for TenantB
    Map<String, String> encryptionContextB = new HashMap<>();
    encryptionContextB.put("tenant", "TenantB");
    encryptionContextB.put("encryption", "context");
    encryptionContextB.put("is not", "secret");
    encryptionContextB.put("but adds", "useful metadata");
    encryptionContextB.put("that can help you", "be confident that");
    encryptionContextB.put("the data you are handling", "is what you think it is");

    final int numThreads = 1000;
    final ConcurrentHashMap<String, Integer> sharedMap = new ConcurrentHashMap<>();
    AtomicInteger counter = new AtomicInteger(0);

    ExecutorService executor = Executors.newFixedThreadPool(numThreads);

    for (int i = 0; i < numThreads; i++) {
      final int threadNumber = i;
      executor.execute(
          () -> {
            // Encrypt the data for encryptionContextA & encryptionContextB
            final CryptoResult<byte[], ?> encryptResultA =
                crypto.encryptData(hierarchicalKeyring, EXAMPLE_DATA, encryptionContextA);
            final CryptoResult<byte[], ?> encryptResultB =
                crypto.encryptData(hierarchicalKeyring, EXAMPLE_DATA, encryptionContextB);

            // Decrypt your encrypted data using the same keyring you used on encrypt.
            final CryptoResult<byte[], ?> decryptResultA =
                crypto.decryptData(hierarchicalKeyring, encryptResultA.getResult());
            assert Arrays.equals(decryptResultA.getResult(), EXAMPLE_DATA);

            final CryptoResult<byte[], ?> decryptResultB =
                crypto.decryptData(hierarchicalKeyring, encryptResultB.getResult());
            assert Arrays.equals(decryptResultB.getResult(), EXAMPLE_DATA);

            // Increment the counter
            counter.incrementAndGet();
          });
    }

    executor.shutdown();

    while (!executor.isTerminated()) {
      // Wait for all threads to finish.
    }

    System.out.println("All threads have completed.");

    // Ensure thread safety by checking the map's size
    if (counter.get() == numThreads) {
      System.out.println("Thread safety maintained.");
    } else {
      System.out.println("Thread safety not maintained.");
    }
  }

  public static void main(final String[] args) {
    if (args.length <= 0) {
      throw new IllegalArgumentException(
          "To run this example, include the keyStoreTableName, logicalKeyStoreName, and kmsKeyId in args");
    }
    final String keyStoreTableName = args[0];
    final String logicalKeyStoreName = args[1];
    final String kmsKeyId = args[2];
    encryptAndDecryptWithKeyring(keyStoreTableName, logicalKeyStoreName, kmsKeyId);
  }
}
