package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.concurrent;

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import com.amazonaws.crypto.examples.mpl_mutation_examples.DdbHelper;
import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.*;
import software.amazon.cryptography.keystoreadmin.KeyStoreAdmin;
import software.amazon.cryptography.keystoreadmin.model.CreateKeyInput;
import software.amazon.cryptography.keystoreadmin.model.CreateKeyOutput;
import software.amazon.cryptography.keystoreadmin.model.KeyStoreAdminConfig;
import software.amazon.cryptography.keystoreadmin.model.KmsSymmetricKeyArn;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

// This class contains a suite of tests to check behavior in the storage layer
// of the library's APIs. These APIs write using the storage layer and .
// This class contains a suite of tests to check behavior in the storage layer
// of the library's APIs. These APIs write using the storage layer and .
public class StorageWriteReadConcurrencyTests {

  private static final String branchKeyId =
          "concurrency-test-write-key-" + UUID.randomUUID();
  private static final Integer threadCount = 15;
  private static final List<String> identifiers = Collections.unmodifiableList(
          Arrays.asList(
                  IntStream
                          .rangeClosed(1, 15)
                          .mapToObj(String::valueOf)
                          .toArray(String[]::new)
          )
  );

  private Map<String, Storage> threadIndexToStorage;
  private Map<String, KeyStore> threadIndexToKeyStore;
  private static Map<String, String> indexToThreadId;
  private static Map<
          String,
          GetActiveBranchKeyOutput
          > getActiveBranchKeyOutputs;
  private ConcurrentLinkedDeque<
          String
          > unpickedIndicesForStorage, unpickedIndicesForKeyStore;
  private static Map<String, String> encryptionContext;
  private static final AtomicInteger counter = new AtomicInteger(0);
  private static final TimeZone timeZone = TimeZone.getTimeZone("UTC");
  private static final DateFormat dateFormat = new SimpleDateFormat(
          "yyyy-MM-dd'T'HH:mm:ss.SSSSS'Z'"
  );

  @BeforeClass
  public void setup() {
    dateFormat.setTimeZone(timeZone);
    threadIndexToStorage = new ConcurrentHashMap<>(16, 1, threadCount);
    threadIndexToKeyStore = new ConcurrentHashMap<>(16, 1, threadCount);
    indexToThreadId = new ConcurrentHashMap<>(16, 1, threadCount);
    getActiveBranchKeyOutputs = new ConcurrentHashMap<>(16, 1, threadCount);

    unpickedIndicesForStorage = new ConcurrentLinkedDeque<>(identifiers);
    unpickedIndicesForKeyStore = new ConcurrentLinkedDeque<>(identifiers);
    // For every identifier which will ultimately map to one thread, we will create a unique
    // storage layer per thread with a unique ddb client. This will make it so that
    // we isolate resources even further and prevent resource reuse.
    identifiers.forEach(id -> {
      threadIndexToStorage.put(id, createStorageLayer());
      threadIndexToKeyStore.put(id, createKeyStore());
    });

    encryptionContext = new HashMap<>();
    encryptionContext.put("custom", "ec");
  }

  @AfterClass
  public void teardown() {
    DdbHelper.DeleteBranchKey(
            branchKeyId,
            Fixtures.TEST_KEYSTORE_NAME,
            null,
            null
    );
  }

  public static KeyStore createKeyStore() {
    final DynamoDbClient _ddbClient = DynamoDbClient.create();
    final KmsClient _kmsClient = KmsClient.create();
    final KeyStoreConfig config = KeyStoreConfig
            .builder()
            .ddbClient(_ddbClient)
            .ddbTableName(Fixtures.TEST_KEYSTORE_NAME)
            .logicalKeyStoreName(Fixtures.TEST_KEYSTORE_NAME)
            .kmsClient(_kmsClient)
            .kmsConfiguration(
                    KMSConfiguration.builder().kmsKeyArn(Fixtures.KEYSTORE_KMS_ARN).build()
            )
            .build();
    return KeyStore.builder().KeyStoreConfig(config).build();
  }

  public static Storage createStorageLayer() {
    final DynamoDbClient _ddbClient = DynamoDbClient.create();
    DynamoDBTable table = DynamoDBTable
            .builder()
            .ddbClient(_ddbClient)
            .ddbTableName(Fixtures.TEST_KEYSTORE_NAME)
            .build();
    return Storage.builder().ddb(table).build();
  }

  private Storage storageForThread(final String threadIdToIndex) {
    return threadIndexToStorage.computeIfAbsent(
            threadIdToIndex,
            k -> createStorageLayer()
    );
  }

  private KeyStore keyStoreForThread(String threadIdToIndex) {
    return threadIndexToKeyStore.computeIfAbsent(
            threadIdToIndex,
            k -> createKeyStore()
    );
  }

  private CreateKeyOutput raceToWriteWithStorage(KeyStoreAdmin admin) {
    CreateKeyInput createKeyInput = CreateKeyInput
            .builder()
            .Identifier(branchKeyId)
            .EncryptionContext(encryptionContext)
            .KmsArn(
                    KmsSymmetricKeyArn
                            .builder()
                            .KmsKeyArn(Fixtures.KEYSTORE_KMS_ARN)
                            .build()
            )
            .build();
    return admin.CreateKey(createKeyInput);
  }

  private GetActiveBranchKeyOutput raceToReadWithKeyStore(KeyStore keyStore) {
    GetActiveBranchKeyInput input = GetActiveBranchKeyInput
            .builder()
            .branchKeyIdentifier(branchKeyId)
            .build();
    return keyStore.GetActiveBranchKey(input);
  }

  @Test(threadPoolSize = 15, invocationCount = 150, timeOut = 10000)
  public void testConcurrentStorage() {
    String threadId = String.valueOf(Thread.currentThread().getId());
    String threadIdToIndex = indexToThreadId.computeIfAbsent(
            threadId,
            str -> unpickedIndicesForStorage.pop()
    );

    String timestamp = dateFormat.format(new Date());

    try {
      if (Integer.parseInt(threadIdToIndex) % 2 == 0) {
        Storage threadStorage = storageForThread(threadIdToIndex);
        KeyStoreAdminConfig keyStoreAdminConfig = KeyStoreAdminConfig
                .builder()
                .storage(threadStorage)
                .logicalKeyStoreName(Fixtures.TEST_KEYSTORE_NAME)
                .build();
        KeyStoreAdmin admin = KeyStoreAdmin
                .builder()
                .KeyStoreAdminConfig(keyStoreAdminConfig)
                .build();
        raceToWriteWithStorage(admin);
        System.out.println(
                "Successfully wrote! Thread ID: " +
                        Thread.currentThread().getId() +
                        " ThreadIndex: " +
                        threadIdToIndex +
                        " Timestamp: " +
                        timestamp +
                        " BranchKeyId: " +
                        branchKeyId
        );
      } else {
        String iteration = String.valueOf(counter.incrementAndGet());
        KeyStore keyStore = keyStoreForThread(threadIdToIndex);
        GetActiveBranchKeyOutput output = raceToReadWithKeyStore(keyStore);
        getActiveBranchKeyOutputs.put(iteration, output);
        System.out.println("Successfully read branch key: " + branchKeyId);
      }
    } catch (TransactionCanceledException exception) {
      System.out.println("Failed to write branch key: " + branchKeyId);
      // Exceptions that get thrown when you write keys using the Storage interface
      exception
              .cancellationReasons()
              .forEach(cancellationReason -> {
                Assert.assertTrue(
                        (cancellationReason.code().equals("TransactionConflict") ||
                                cancellationReason.code().equals("None") ||
                                cancellationReason.code().equals("ConditionalCheckFailed"))
                );
              });
    } catch (KeyStorageException | KeyStoreException e) {
      System.out.println("Failed to read branch key: " + branchKeyId);
      // Exceptions that get thrown when you read keys using the KeyStore interface.
      Assert.assertEquals(
              e.getMessage(),
              "No item found for corresponding branch key identifier."
      );
    }
  }

  @Test(dependsOnMethods = { "testConcurrentStorage" })
  public void testReadAfterWriteCheck() {
    // Iterate through the values and check that it equals the first item in the map,
    // if there are any difference the test will fail.
    System.out.println(getActiveBranchKeyOutputs.size());
    GetActiveBranchKeyOutput first = getActiveBranchKeyOutputs
            .values()
            .iterator()
            .next();
    for (GetActiveBranchKeyOutput value : getActiveBranchKeyOutputs.values()) {
      Assert.assertEquals(
              value.branchKeyMaterials().branchKey(),
              first.branchKeyMaterials().branchKey()
      );
    }
  }
}
