package com.amazonaws.crypto.examples.mpl_mutation_examples;

import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.AdminProvider;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


public class DdbHelper {

  public static boolean deleteKeyStoreDdbItem(
    final String branchKeyId,
    final String branchKeyType,
    final String physicalName,
    @Nullable DynamoDbClient dynamoDbClient,
    boolean verbose
  ) {
    return reallyDeleteKeyStoreDdbItem(
      branchKeyId,
      branchKeyType,
      physicalName,
      1,
      0,
      AdminProvider.dynamoDB(dynamoDbClient),
      verbose
    );
  }

  public static boolean reallyDeleteKeyStoreDdbItem(
    final String branchKeyId,
    final String branchKeyType,
    final String physicalName,
    int retryCount,
    final int sleep,
    final DynamoDbClient dynamoDbClient,
    boolean verbose
  ) {
    Map<String, AttributeValue> ddbKey = new HashMap<>(3, 1);
    ddbKey.put(
      Constants.BRANCH_KEY_ID,
      AttributeValue.builder().s(branchKeyId).build()
    );
    ddbKey.put(
      Constants.TYPE,
      AttributeValue.builder().s(branchKeyType).build()
    );
    DeleteItemRequest deleteReq = DeleteItemRequest
      .builder()
      .tableName(physicalName)
      .key(ddbKey)
      .returnValues(ReturnValue.ALL_OLD)
      .build();
    DeleteItemResponse deleteRes;
    GetItemRequest getReq = GetItemRequest
      .builder()
      .key(ddbKey)
      .tableName(physicalName)
      .build();
    GetItemResponse getRes;
    boolean done = false;
    while (retryCount > 0 && !done) {
      deleteRes = dynamoDbClient.deleteItem(deleteReq);
      getRes = dynamoDbClient.getItem(getReq);
      if (deleteRes.hasAttributes()) {
        if (verbose) {
          System.out.println(
            "Deleted with result: " + deleteRes.attributes().get(Constants.TYPE)
          );
        }
      }
      if (getRes.hasItem()) {
        if (verbose) {
          System.out.println(
            "Got with result: " + getRes.item().get(Constants.TYPE)
          );
        }
        retryCount--;
        try {
          Thread.sleep(sleep);
        } catch (InterruptedException e) {
          throw new RuntimeException(e);
        }
      } else {
        if (verbose) {
          System.out.println("Got no result.");
        }
        done = true;
      }
    }
    return done;
  }

  public static GetItemResponse getKeyStoreDdbItem(
    final String branchKeyId,
    final String branchKeyType,
    final String physicalName,
    @Nullable DynamoDbClient dynamoDbClient
  ) {
    Map<String, AttributeValue> ddbKey = new HashMap<>(3);
    ddbKey.put(
      Constants.BRANCH_KEY_ID,
      AttributeValue.builder().s(branchKeyId).build()
    );
    ddbKey.put(
      Constants.TYPE,
      AttributeValue.builder().s(branchKeyType).build()
    );
    return AdminProvider
      .dynamoDB(dynamoDbClient)
      .getItem(builder -> builder.tableName(physicalName).key(ddbKey));
  }

  public static GetItemResponse getKeyStoreDdbItemAttribute(
          final String branchKeyId,
          final String branchKeyType,
          final String physicalName,
          final String attributeName,
          @Nullable DynamoDbClient dynamoDbClient
  ) {
    Map<String, AttributeValue> ddbKey = new HashMap<>(3);
    ddbKey.put(
            Constants.BRANCH_KEY_ID,
            AttributeValue.builder().s(branchKeyId).build()
    );
    ddbKey.put(
            Constants.TYPE,
            AttributeValue.builder().s(branchKeyType).build()
    );
    return AdminProvider
            .dynamoDB(dynamoDbClient)
            .getItem(builder -> builder.tableName(physicalName).key(ddbKey).attributesToGet(attributeName));
  }

  private static TransactWriteItem bkItemToDeleteReq(
    final Map<String, AttributeValue> key,
    final String _tableName
  ) {
    assert key.size() == 2 : "key parameter should only have 2 items";
    return TransactWriteItem
      .builder()
      .delete(Delete.builder().tableName(_tableName).key(key).build())
      .build();
  }

  private static Map<String, AttributeValue> itemToDDBKey(
    Map<String, AttributeValue> item
  ) {
    final Map<String, AttributeValue> key = new HashMap<>(3, 1);
    assert item.get(Constants.BRANCH_KEY_ID) != null : Constants.BRANCH_KEY_ID +
    " should not be null";
    assert item.get(Constants.TYPE) != null : Constants.TYPE +
    " should not be null";
    key.put(Constants.BRANCH_KEY_ID, item.get(Constants.BRANCH_KEY_ID));
    key.put(Constants.TYPE, item.get(Constants.TYPE));
    return key;
  }

  public static boolean DeleteBranchKey(
    final String branchKeyId,
    @Nullable String tableName,
    @Nullable String hierarchyVersion,
    @Nullable DynamoDbClient ddbClient
  ) {
    final String _tableName = tableName == null
      ? Fixtures.TEST_KEYSTORE_NAME
      : tableName;
    final String _hierarchyVersion = hierarchyVersion == null
      ? "1"
      : hierarchyVersion;
    final DynamoDbClient _ddbClient = ddbClient == null
      ? Fixtures.ddbClientWest2
      : ddbClient;
    final List<Map<String, AttributeValue>> ddbKeys = QueryForAllBkItemsDDBKeys(
      branchKeyId,
      _tableName,
      _hierarchyVersion,
      _ddbClient
    );
    return DeleteAllBkKeys(ddbKeys, _tableName, _ddbClient);
  }

  public static boolean DeleteAllBkKeys(
    @Nonnull List<Map<String, AttributeValue>> ddbKeys,
    @Nullable String tableName,
    @Nullable DynamoDbClient ddbClient
  ) {
    final String _tableName = tableName == null
      ? Fixtures.TEST_KEYSTORE_NAME
      : tableName;
    final DynamoDbClient _ddbClient = ddbClient == null
      ? Fixtures.ddbClientWest2
      : ddbClient;
    final List<TransactWriteItem> deleteItems = ddbKeys
      .stream()
      .map(item -> bkItemToDeleteReq(item, _tableName))
      .collect(Collectors.toList());
    if (deleteItems.isEmpty()) {
      return true;
    }
    final TransactWriteItemsRequest deleteReq = TransactWriteItemsRequest
      .builder()
      .transactItems(
        deleteItems.size() > 100 ? deleteItems.subList(0, 100) : deleteItems
      )
      .build();
    _ddbClient.transactWriteItems(deleteReq);
    return deleteItems.size() < 100;
  }

  public static List<Map<String, AttributeValue>> QueryForAllBkItemsDDBKeys(
    final String branchKeyId,
    @Nullable String tableName,
    @Nullable String hierarchyVersion,
    @Nullable DynamoDbClient ddbClient
  ) {
    final String _tableName = tableName == null
      ? Fixtures.TEST_KEYSTORE_NAME
      : tableName;
    final String _hierarchyVersion = hierarchyVersion == null
      ? "1"
      : hierarchyVersion;
    final DynamoDbClient _ddbClient = ddbClient == null
      ? Fixtures.ddbClientWest2
      : ddbClient;
    final QueryResponse queryRes = queryForAllBkItems(
      branchKeyId,
      _hierarchyVersion,
      _tableName,
      _ddbClient
    );
    return queryRes
      .items()
      .stream()
      .map(DdbHelper::itemToDDBKey)
      .collect(Collectors.toList());
  }

  private static QueryResponse queryForAllBkItems(
    String branchKeyId,
    String _hierarchyVersion,
    String _tableName,
    DynamoDbClient _ddbClient
  ) {
    final Map<String, String> ExpressionAttributeNames = new HashMap<>(3, 1);
    ExpressionAttributeNames.put("#pk", Constants.BRANCH_KEY_ID);
    ExpressionAttributeNames.put("#hv", "hierarchy-version");
    final Map<String, AttributeValue> ExpressionAttributeValues = new HashMap<>(
      3,
      1
    );
    ExpressionAttributeValues.put(":pk", AttributeValue.fromS(branchKeyId));
    ExpressionAttributeValues.put(
      ":hv",
      AttributeValue.fromN(_hierarchyVersion)
    );
    final QueryRequest queryReq = QueryRequest
      .builder()
      .tableName(_tableName)
      .keyConditionExpression("#pk = :pk")
      .filterExpression("#hv = :hv")
      .expressionAttributeNames(ExpressionAttributeNames)
      .expressionAttributeValues(ExpressionAttributeValues)
      .build();
    return _ddbClient.query(queryReq);
  }
}
