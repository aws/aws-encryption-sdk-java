package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations;

import com.amazonaws.crypto.examples.mpl_mutation_examples.Constants;
import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * It is a best practice to routinely scan for in-complete Mutations.
 * An in-complete Mutation occurs whenever a Mutation is started but not completed;
 * this can happen if a host crashes while Applying a Mutation.
 * An in-complete Mutation leaves a Branch Key in a mixed state.
 * Presumably, both states are safe, but it is a Best Practice to
 * keep a Branch Key in one consistent state.
 * Otherwise, reasoning about the Security domain of the Branch Key is difficult.
 * This class scans a DynamoDB table for the items persisted by {@code InitializeMutation}.
 * When a Mutation is completed
 * (by calling {@code ApplyMutation} until it returns {@code CompleteMutation})
 * these items are deleted by {@code ApplyMutation}.
 * Thus, there presence alone indicates
 * that a Mutation is in-flight for a Branch Key. <p>
 * Note: <strong>Do not manually delete these items.</strong>
 * Doing so prevents the library from
 * ensuring a Mutation is consistently applied
 * to all versions of a Branch Key.
 */
public class ScanForInFlightMutations {

  @Nonnull
  private final DynamoDbClient dynamoDbClient;

  @Nonnull
  private final String tableName;

  @Nullable
  private final Integer limit;

  private static final Map<String, String> EAN;
  private static final Map<String, AttributeValue> EAV;
  private static final String PE = "#pk, #sk, #ct";

  static {
    EAN = new HashMap<>(4, 1);
    EAN.put("#sk", Constants.TYPE);
    EAN.put("#pk", Constants.BRANCH_KEY_ID);
    EAN.put("#ct", Constants.CREATE_TIME);
    EAV = new HashMap<>(2, 1);
    EAV.put(
      ":sk",
      AttributeValue.builder().s(Constants.TYPE_MUTATION_COMMITMENT).build()
    );
  }

  public ScanForInFlightMutations(
    @Nonnull DynamoDbClient dynamoDbClient,
    @Nonnull String tableName,
    @Nullable Integer limit
  ) {
    this.dynamoDbClient = dynamoDbClient;
    this.tableName = tableName;
    this.limit = limit;
  }

  public static class InFlightMutation {

    private final String branchKeyID;
    private final String createTime;

    public InFlightMutation(String branchKeyID, String createTime) {
      this.branchKeyID = branchKeyID;
      this.createTime = createTime;
    }

    public String branchKeyID() {
      return branchKeyID;
    }

    public String createTime() {
      return createTime;
    }

    @Override
    public String toString() {
      return branchKeyID + ": " + createTime;
    }
  }

  public static class PageResult {

    private final @Nonnull List<InFlightMutation> inFlightMutations;
    private final @Nullable Map<String, AttributeValue> lastEvaluatedKey;

    public PageResult(
      @Nonnull List<InFlightMutation> inFlightMutations,
      @Nullable Map<String, AttributeValue> lastEvaluatedKey
    ) {
      this.inFlightMutations = inFlightMutations;
      this.lastEvaluatedKey = lastEvaluatedKey;
    }

    public @Nonnull List<InFlightMutation> inFlightMutations() {
      return inFlightMutations;
    }

    public @Nullable Map<String, AttributeValue> lastEvaluatedKey() {
      return lastEvaluatedKey;
    }
  }

  public PageResult scanForMutationCommitment(
    @Nullable Map<String, AttributeValue> exclusiveStartKey
  ) {
    ScanRequest.Builder request = ScanRequest
      .builder()
      .tableName(tableName)
      .filterExpression("#sk = :sk")
      .expressionAttributeNames(EAN)
      .expressionAttributeValues(EAV)
      .projectionExpression(PE);
    if (exclusiveStartKey != null) {
      request.exclusiveStartKey(exclusiveStartKey);
    }
    if (limit != null) {
      request.limit(limit);
    }
    ScanResponse response = this.dynamoDbClient.scan(request.build());
    Map<String, AttributeValue> lastEvaluatedKey = response.lastEvaluatedKey();
    List<InFlightMutation> list = new ArrayList<>();
    for (Map<
      String,
      AttributeValue
    > stringAttributeValueMap : response.items()) {
      String bkid = stringAttributeValueMap.get(Constants.BRANCH_KEY_ID).s();
      String createTime = stringAttributeValueMap
        .get(Constants.CREATE_TIME)
        .s();
      InFlightMutation apply = new InFlightMutation(bkid, createTime);
      list.add(apply);
    }
    if (lastEvaluatedKey != null && !lastEvaluatedKey.isEmpty()) {
      return new PageResult(list, lastEvaluatedKey);
    }
    return new PageResult(list, null);
  }

  public static void Example() {
    ScanForInFlightMutations scanner = new ScanForInFlightMutations(
      Fixtures.ddbClientWest2,
      Fixtures.TEST_KEYSTORE_NAME,
      null
    );
    PageResult actual = scanner.scanForMutationCommitment(null);
    System.out.println(actual);
  }
}
