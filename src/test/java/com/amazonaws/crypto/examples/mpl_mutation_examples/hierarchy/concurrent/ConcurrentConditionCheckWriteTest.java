package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.concurrent;

import com.amazonaws.crypto.examples.mpl_mutation_examples.DdbHelper;
import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.utils.ImmutableMap;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;


// These concurrent tests check that DynamoDB behaves the way we expect when
// there are multiple request to write an item to DynamoDB. Our libraries use the
// TransactWriteItems API with a condition check that the primary key we are writing
// does not exist. This will result in either 1. ConditionCheckFailure if an item has been
// written, and we are trying to write over it and 2. TransactionConflict if we are trying to write
// while there is a transaction being committed.
public class ConcurrentConditionCheckWriteTest {

  private static final Integer threadCount = 5;
  private static final String mLockedId = "concurrency-test-write-key";
  private static final Map<String, String> INDEX_EXPR_ATT_NAMES =
    ImmutableMap.of("#pk", "branch-key-id");

  private static final List<String> identifiers = Collections.unmodifiableList(
    Arrays.asList("1", "2", "3", "4", "5")
  );
  private Map<String, DynamoDbClient> threadIdToDdbClient;
  private static Map<String, String> indexToThreadId;
  private ConcurrentLinkedDeque<String> unpickedIndices;

  @BeforeClass
  public void setup() {
    threadIdToDdbClient = new ConcurrentHashMap<>(6, 1, threadCount);
    identifiers.forEach(id ->
      threadIdToDdbClient.put(id, DynamoDbClient.create())
    );
    indexToThreadId = new ConcurrentHashMap<>(6, 1, threadCount);
    unpickedIndices = new ConcurrentLinkedDeque<>(identifiers);
  }

  @AfterClass
  public void teardown() {
    DynamoDbClient _ddbClient = DynamoDbClient.create();
    identifiers.forEach(id ->
      DdbHelper.deleteKeyStoreDdbItem(
        mLockedId,
        "branch:ACTIVE",
        Fixtures.TEST_KEYSTORE_NAME,
        _ddbClient,
        true
      )
    );
  }

  public static Map<String, AttributeValue> indexItem(
    final AttributeValue value,
    final String timestamp
  ) {
    Map<String, AttributeValue> item = new HashMap<>();

    item.put("branch-key-id", AttributeValue.builder().s(mLockedId).build());
    item.put("type", AttributeValue.builder().s(indexType()).build());
    item.put("value", value);
    item.put("timestamp", AttributeValue.builder().s(timestamp).build());
    return item;
  }

  private static String indexType() {
    return "branch:ACTIVE";
  }

  public static TransactWriteItem conditionalWrite(
    final AttributeValue value,
    final String timestamp
  ) {
    return TransactWriteItem
      .builder()
      .put(putBuilder ->
        putBuilder
          .tableName(Fixtures.TEST_KEYSTORE_NAME)
          .item(indexItem(value, timestamp))
          .conditionExpression("attribute_not_exists(#pk)")
          .expressionAttributeNames(INDEX_EXPR_ATT_NAMES)
      )
      .build();
  }

  private DynamoDbClient clientForThread(final String threadIdToIndex) {
    return threadIdToDdbClient.computeIfAbsent(
      threadIdToIndex,
      ddbClient -> DynamoDbClient.create()
    );
  }

  @Test(threadPoolSize = 5, invocationCount = 30, timeOut = 1000)
  public void TestConcurrentWriteCheck() {
    String threadId = String.valueOf(Thread.currentThread().getId());
    String threadIdToIndex = indexToThreadId.computeIfAbsent(
      threadId,
      str -> unpickedIndices.pop()
    );
    AttributeValue value = AttributeValue.builder().s(threadIdToIndex).build();
    TimeZone tz = TimeZone.getTimeZone("UTC");
    DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSS'Z'"); // Quoted "Z" to indicate UTC, no timezone offset
    df.setTimeZone(tz);
    String timestamp = df.format(new Date());

    System.out.println(
      "Thread ID: " +
      Thread.currentThread().getId() +
      " ThreadIndex: " +
      threadIdToIndex +
      " Timestamp: " +
      timestamp
    );

    try {
      DynamoDbClient client = clientForThread(threadIdToIndex);
      TransactWriteItemsResponse transactWriteItemsResponse =
        client.transactWriteItems(
          TransactWriteItemsRequest
            .builder()
            .transactItems(conditionalWrite(value, timestamp))
            .build()
        );
      Assert.assertTrue(
        transactWriteItemsResponse.sdkHttpResponse().isSuccessful()
      );
    } catch (TransactionCanceledException exception) {
      // We can fail for two reasons, either there's already a transact write in flight
      // 0r we have failed the condition check.
      exception
        .cancellationReasons()
        .forEach(cancellationReason -> {
          Assert.assertTrue(
            (cancellationReason.code().equals("TransactionConflict") ||
              cancellationReason.code().equals("ConditionalCheckFailed"))
          );
        });
    }
  }
}
