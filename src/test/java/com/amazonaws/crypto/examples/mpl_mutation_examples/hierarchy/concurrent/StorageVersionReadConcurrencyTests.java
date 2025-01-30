package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.concurrent;

import com.amazonaws.crypto.examples.mpl_mutation_examples.DdbHelper;
import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.DynamoDBTable;
import software.amazon.cryptography.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.keystore.model.GetActiveBranchKeyOutput;
import software.amazon.cryptography.keystore.model.Storage;
import software.amazon.cryptography.keystoreadmin.KeyStoreAdmin;
import software.amazon.cryptography.keystoreadmin.model.CreateKeyInput;
import software.amazon.cryptography.keystoreadmin.model.KeyStoreAdminConfig;
import software.amazon.cryptography.keystoreadmin.model.KmsSymmetricKeyArn;
import software.amazon.cryptography.keystoreadmin.model.VersionKeyInput;

import java.nio.ByteBuffer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.concurrent.StorageWriteReadConcurrencyTests.createKeyStore;
import static com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.concurrent.StorageWriteReadConcurrencyTests.createStorageLayer;

// This class contains a suite of tests that check for behavior of reading
// a branch key while a version operation is in flight.
// The expectation of these tests is that for an already existing Branch Key
// if there is a race to version the key, we will always be able to read the ACTIVE key.
public class StorageVersionReadConcurrencyTests {

  private static final String branchKeyId =
          "concurrency-test-version-key-" + UUID.randomUUID();
  private static final Integer threadCount = 10;
  private static final List<String> identifiers = Collections.unmodifiableList(
          Arrays.asList(
                  IntStream
                          .rangeClosed(1, 10)
                          .mapToObj(String::valueOf)
                          .toArray(String[]::new)
          )
  );

  private Map<String, Storage> threadIndexToStorage;
  private Map<String, KeyStore> threadIndexToKeyStore;
  private static Map<
          String,
          String
          > storageIndexToThreadId, keyStoreIndexToThreadId;
  private static Map<String, ByteBuffer> versionKeyOutputMap;
  private ConcurrentLinkedDeque<
          String
          > unpickedIndicesForStorage, unpickedIndicesForKeyStore;
  private static Map<String, String> encryptionContext;
  private static final AtomicInteger counter = new AtomicInteger(0);
  private static final TimeZone timeZone = TimeZone.getTimeZone("UTC");
  private static final DateFormat dateFormat = new SimpleDateFormat(
          "yyyy-MM-dd'T'HH:mm:ss.SSSSS'Z'"
  );
  private static final QueryRequest queryRequestForCleanUp = QueryRequest
          .builder()
          .tableName(Fixtures.TEST_KEYSTORE_NAME)
          .keyConditionExpression("#pk = :pkval")
          .expressionAttributeNames(
                  new HashMap<String, String>() {
                    {
                      put("#pk", "branch-key-id");
                    }
                  }
          )
          .expressionAttributeValues(
                  new HashMap<String, AttributeValue>() {
                    {
                      put(":pkval", AttributeValue.builder().s(branchKeyId).build());
                    }
                  }
          )
          .build();

  @BeforeClass
  public void setup() {
    dateFormat.setTimeZone(timeZone);
    threadIndexToStorage = new ConcurrentHashMap<>(16, 1, threadCount);
    threadIndexToKeyStore = new ConcurrentHashMap<>(16, 1, threadCount);
    storageIndexToThreadId = new ConcurrentHashMap<>(16, 1, threadCount);
    keyStoreIndexToThreadId = new ConcurrentHashMap<>(16, 1, threadCount);
    versionKeyOutputMap = new ConcurrentHashMap<>(16, 1, threadCount);

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

    final DynamoDbClient _ddbClient = DynamoDbClient.create();
    DynamoDBTable table = DynamoDBTable
            .builder()
            .ddbClient(_ddbClient)
            .ddbTableName(Fixtures.TEST_KEYSTORE_NAME)
            .build();
    Storage tmp = Storage.builder().ddb(table).build();
    KeyStoreAdmin admin = KeyStoreAdmin
            .builder()
            .KeyStoreAdminConfig(
                    KeyStoreAdminConfig
                            .builder()
                            .storage(tmp)
                            .logicalKeyStoreName(Fixtures.TEST_KEYSTORE_NAME)
                            .build()
            )
            .build();
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
    admin.CreateKey(createKeyInput);
    System.out.println(
            "Successfully set up test with branch key: " + branchKeyId
    );
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

  private void raceToVersionWithStorage(KeyStoreAdmin admin) {
    VersionKeyInput input = VersionKeyInput
            .builder()
            .Identifier(branchKeyId)
            .KmsArn(
                    KmsSymmetricKeyArn
                            .builder()
                            .KmsKeyArn(Fixtures.KEYSTORE_KMS_ARN)
                            .build()
            )
            .build();
    admin.VersionKey(input);
  }

  private GetActiveBranchKeyOutput raceToReadActiveWithKeyStore(
          KeyStore keyStore
  ) {
    GetActiveBranchKeyInput input = GetActiveBranchKeyInput
            .builder()
            .branchKeyIdentifier(branchKeyId)
            .build();
    return keyStore.GetActiveBranchKey(input);
  }

  // For test testConcurrentVersionWithStorage - we fire 10 * 100 request to version the branch key,
  //    since when we version we also use a condition check we could fail because there is a transaction
  //    in flight, or we failed the condition check. The TransactionConflict error can happen if there
  //    are requests all trying to race to write the version, since only 1 will win there will be threads that error
  //    with TransactionConflict and some that fail with ConditionalCheckFailed because the requests that are lining up
  //    with the same partition key and sort key value will fail the conditional check.
  @Test(threadPoolSize = 10, invocationCount = 100, timeOut = 10000)
  public void testConcurrentVersionWithStorage() {
    String threadId = String.valueOf(Thread.currentThread().getId());
    String threadIdToIndex = storageIndexToThreadId.computeIfAbsent(
            threadId,
            str -> unpickedIndicesForStorage.pop()
    );

    String timestamp = dateFormat.format(new Date());
    try {
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
      raceToVersionWithStorage(admin);
      System.out.println(
              "Successfully versioned branch key! Thread ID: " +
                      Thread.currentThread().getId() +
                      " ThreadIndex: " +
                      threadIdToIndex +
                      " Timestamp: " +
                      timestamp +
                      " BranchKeyId: " +
                      branchKeyId
      );
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
    }
  }

  // For test testConcurrentActiveReadWhileVersionInFlight, the expectation of this test is that if
  //    we fire 10 * 100 read requests on the active item we will always be able to read the
  //    active branch key. This test has no asserts since the "pointer" to the branch key is changing
  //    so it is not helpful to assert that the version of the active is the same since it is meant to
  //    change as these tests execute in parallel.
  //    There are no catch statements here since we expect to always be able to read, if any
  //    error is thrown the test fails.
  @Test(threadPoolSize = 10, invocationCount = 100, timeOut = 10000)
  public void testConcurrentActiveReadWhileVersionInFlight() {
    // Since on set up we create a branch key, we should always be able to read.
    String threadId = String.valueOf(Thread.currentThread().getId());
    String threadIdToIndex = keyStoreIndexToThreadId.computeIfAbsent(
            threadId,
            str -> unpickedIndicesForKeyStore.pop()
    );
    KeyStore keyStore = keyStoreForThread(threadIdToIndex);
    GetActiveBranchKeyOutput output = raceToReadActiveWithKeyStore(keyStore);
    versionKeyOutputMap.put(
            output.branchKeyMaterials().branchKeyVersion(),
            output.branchKeyMaterials().branchKey()
    );
    System.out.println(
            "Successfully read branch key: " +
                    branchKeyId +
                    " with version: " +
                    output.branchKeyMaterials().branchKeyVersion()
    );
  }

  // This test is more of a sanity check that we were always able to read something.
  // If you were able to look at the table and how many new versions were created
  // and how many versions we were able to read, one would see very different results. We end
  // up writing more new versions than the ones we were able to read. This is because reading
  // is faster than writing.
  @Test(
          dependsOnMethods = {
                  "testConcurrentActiveReadWhileVersionInFlight",
                  "testConcurrentVersionWithStorage",
          }
  )
  public void testVersionReads() {
    Assert.assertFalse(versionKeyOutputMap.isEmpty());
    for (String key : versionKeyOutputMap.keySet()) {
      System.out.println(
              "key: " + key + " value " + versionKeyOutputMap.get(key)
      );
    }
  }
}
