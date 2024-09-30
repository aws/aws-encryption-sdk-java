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
import software.amazon.cryptography.materialproviders.CryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsCache;
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
 * This example demonstrates how to use a shared cache across multiple Hierarchical Keyrings.
 * With this functionality, users only need to maintain one common shared cache across multiple
 * Hierarchical Keyrings with different Key Stores instances/KMS Clients/KMS Keys.
 * 
 * <p>There are two important parameters that users need to carefully set while providing the shared cache:
 * 
 * <p>Partition ID - Partition ID is an optional parameter provided to the Hierarchical Keyring input,
 * which distinguishes Cryptographic Material Providers (i.e: Keyrings) writing to a cache.
 * - If the Partition ID is set and is the same for two Hierarchical Keyrings (or another Material Provider),
 *   they CAN share the same cache entries in the cache.
 * - If the Partition ID is set and is different for two Hierarchical Keyrings (or another Material Provider),
 *   they CANNOT share the same cache entries in the cache.
 * - If the Partition ID is not set by the user, it is initialized as a random 16-byte UUID which makes
 *   it unique for every Hierarchical Keyring, and two Hierarchical Keyrings (or another Material Provider)
 *   CANNOT share the same cache entries in the cache.
 * 
 * <p>Logical Key Store Name - This parameter is set by the user when configuring the Key Store for
 * the Hierarchical Keyring. This is a logical name for the branch key store.
 * Suppose you have a physical Key Store (K). You create two instances of K (K1 and K2). Now, you create
 * two Hierarchical Keyrings (HK1 and HK2) with these Key Store instances (K1 and K2 respectively).
 * - If you want to share cache entries across these two keyrings, you should set the Logical Key Store Names
 *   for both the Key Store instances (K1 and K2) to be the same.
 * - If you set the Logical Key Store Names for K1 and K2 to be different, HK1 (which uses Key Store instance K1)
 *   and HK2 (which uses Key Store instance K2) will NOT be able to share cache entries.
 * 
 * This is demonstrated in the example below.
 * Notice that both K1 and K2 are instances of the same physical Key Store (K).
 * You MUST NEVER have two different physical Key Stores with the same Logical Key Store Name.
 * 
 * Important Note: If you have two or more Hierarchy Keyrings with:
 * - Same Partition ID
 * - Same Logical Key Store Name of the Key Store for the Hierarchical Keyring 
 * - Same Branch Key ID
 * then they WILL share the cache entries in the Shared Cache.
 * Please make sure that you set all of Partition ID, Logical Key Store Name and Branch Key ID
 * to be the same for two Hierarchical Keyrings if and only if you want them to share cache entries.
 * 
 * <p>This example first creates a shared cache that you can use across multiple Hierarchical Keyrings.
 * The example then configures a Hierarchical Keyring (HK1 and HK2) with the shared cache,
 * a Branch Key ID and two instances (K1 and K2) of the same physical Key Store (K) respectively,
 * i.e. HK1 with K1 and HK2 with K2. The example demonstrates that if you set the same Partition ID
 * for HK1 and HK2, the two keyrings can share cache entries.
 * If you set different Partition ID of the Hierarchical Keyrings, or different
 * Logical Key Store Names of the Key Store instances, then the keyrings will NOT
 * be able to share cache entries.
 *
 * <p>This example requires access to the DDB Table (K) where you are storing the Branch Keys. This
 * table must be configured with the following primary key configuration: - Partition key is named
 * "partition_key" with type (S) - Sort key is named "sort_key" with type (S)
 *
 * <p>This example also requires using a KMS Key. You need the following access on this key:
 * - GenerateDataKeyWithoutPlaintext
 * - Decrypt
 */
public class SharedCacheAcrossHierarchicalKeyringsExample {
  	private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  	public static void encryptAndDecryptWithKeyring(
		String keyStoreTableName, String logicalKeyStoreName, String partitionId, String kmsKeyId) {
		// Create the CryptographicMaterialsCache (CMC) to share across multiple Hierarchical Keyrings
		// using the Material Providers Library
		//    This CMC takes in:
		//     - CacheType
		final MaterialProviders matProv =
			MaterialProviders.builder()
				.MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
				.build();

		final CacheType cache =
			CacheType.builder() 
				.Default(DefaultCache.builder().entryCapacity(100).build())
				.build();

		final CreateCryptographicMaterialsCacheInput cryptographicMaterialsCacheInput =
			CreateCryptographicMaterialsCacheInput.builder()
				.cache(cache)
				.build();

		final ICryptographicMaterialsCache sharedCryptographicMaterialsCache =
			matProv.CreateCryptographicMaterialsCache(cryptographicMaterialsCacheInput);

    	// Create a CacheType object for the sharedCryptographicMaterialsCache
		// Note that the `cache` parameter in the Hierarchical Keyring Input takes a `CacheType` as input
		final CacheType sharedCache =
      		CacheType.builder()
				// This is the `Shared` CacheType that passes an already initialized shared cache
				.Shared(sharedCryptographicMaterialsCache)
				.build();

		// Instantiate the SDK
		// This builds the AwsCrypto client with the RequireEncryptRequireDecrypt commitment policy,
		// which enforces that this client only encrypts using committing algorithm suites and enforces
		// that this client will only decrypt encrypted messages that were created with a committing
		// algorithm suite.
		// This is the default commitment policy if you build the client with
		// `AwsCrypto.builder().build()`
		// or `AwsCrypto.standard()`.
		final AwsCrypto crypto = AwsCrypto.builder().build();

		// Configure your KeyStore resource keystore1.
		//    This SHOULD be the same configuration that you used
		//    to initially create and populate your physical KeyStore.
		// Note that ddbTableName keyStoreTableName is the physical Key Store,
		// and keystore1 is instances of this physical Key Store.
    	final KeyStore keystore1 =
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

		// Call CreateKey to create a new active branch key
		final String branchKeyId =
			keystore1.CreateKey(CreateKeyInput.builder().build()).branchKeyIdentifier();

		// Create the Hierarchical Keyring HK1 with Key Store instance K1, partitionId,
		// the shared Cache and the BranchKeyId.
		// Note that we are now providing an already initialized shared cache instead of just mentioning
		// the cache type and the Hierarchical Keyring initializing a cache at initialization.
		final CreateAwsKmsHierarchicalKeyringInput keyringInput1 =
			CreateAwsKmsHierarchicalKeyringInput.builder()
			.keyStore(keystore1)
			.branchKeyId(branchKeyId)
			.ttlSeconds(600)
			.cache(sharedCache)
			.partitionId(partitionId)
			.build();
		final IKeyring hierarchicalKeyring1 = matProv.CreateAwsKmsHierarchicalKeyring(keyringInput1);

		// Create example encryption context
		Map<String, String> encryptionContext = new HashMap<>();
		encryptionContext.put("encryption", "context");
		encryptionContext.put("is not", "secret");
		encryptionContext.put("but adds", "useful metadata");
		encryptionContext.put("that can help you", "be confident that");
		encryptionContext.put("the data you are handling", "is what you think it is");

		// Encrypt the data for encryptionContext using hierarchicalKeyring1
		final CryptoResult<byte[], ?> encryptResult1 =
			crypto.encryptData(hierarchicalKeyring1, EXAMPLE_DATA, encryptionContext);

		// Decrypt your encrypted data using the same keyring HK1 you used on encrypt.
		final CryptoResult<byte[], ?> decryptResult1 =
			crypto.decryptData(hierarchicalKeyring1, encryptResult1.getResult());
		assert Arrays.equals(decryptResult1.getResult(), EXAMPLE_DATA);

		// Through the above encrypt and decrypt roundtrip, the cache will be populated and
		// the cache entries can be used by another Hierarchical Keyring with the
		// - Same Partition ID
		// - Same Logical Key Store Name of the Key Store for the Hierarchical Keyring 
		// - Same Branch Key ID

		// Configure your KeyStore resource keystore2.
			//    This SHOULD be the same configuration that you used
			//    to initially create and populate your physical KeyStore.
			// Note that ddbTableName keyStoreTableName is the physical Key Store,
			// and keystore2 is instances of this physical Key Store.
		
		// Note that for this example, keystore2 is identical to keystore1.
		// You can optionally change configurations like KMS Client or KMS Key ID based
		// on your use-case.
		// Make sure you have the required permissions to use different configurations.

		// - If you want to share cache entries across two keyrings HK1 and HK2,
		//   you should set the Logical Key Store Names for both
		//   Key Store instances (K1 and K2) to be the same.
		// - If you set the Logical Key Store Names for K1 and K2 to be different,
		//   HK1 (which uses Key Store instance K1) and HK2 (which uses Key Store
		//   instance K2) will NOT be able to share cache entries.
		final KeyStore keystore2 =
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

		// Create the Hierarchical Keyring HK2 with Key Store instance K2, the shared Cache
		// and the same partitionId and BranchKeyId used in HK1 because we want to share cache entries
		// (and experience cache HITS).
		final CreateAwsKmsHierarchicalKeyringInput keyringInput2 =
		CreateAwsKmsHierarchicalKeyringInput.builder()
			.keyStore(keystore2)
			.branchKeyId(branchKeyId)
			.ttlSeconds(600)
			.cache(sharedCache)
			.partitionId(partitionId)
			.build();
		final IKeyring hierarchicalKeyring2 = matProv.CreateAwsKmsHierarchicalKeyring(keyringInput2);

		// This encrypt-decrypt roundtrip with HK2 will experience Cache HITS from previous HK1 roundtrip
		// Encrypt the data for encryptionContext using hierarchicalKeyring2
		final CryptoResult<byte[], ?> encryptResult2 =
			crypto.encryptData(hierarchicalKeyring2, EXAMPLE_DATA, encryptionContext);

		// Decrypt your encrypted data using the same keyring HK2 you used on encrypt.
		final CryptoResult<byte[], ?> decryptResult2 =
			crypto.decryptData(hierarchicalKeyring2, encryptResult2.getResult());
		assert Arrays.equals(decryptResult2.getResult(), EXAMPLE_DATA);
  }

  	public static void main(final String[] args) {
      if (args.length <= 0) {
        throw new IllegalArgumentException(
          "To run this example, include the keyStoreTableName, logicalKeyStoreName, partitionId, and kmsKeyId in args");
      }
      final String keyStoreTableName = args[0];
      final String logicalKeyStoreName = args[1];
      final String partitionId = args[2];
      final String kmsKeyId = args[3];
      encryptAndDecryptWithKeyring(keyStoreTableName, logicalKeyStoreName, partitionId, kmsKeyId);
  	}
}
