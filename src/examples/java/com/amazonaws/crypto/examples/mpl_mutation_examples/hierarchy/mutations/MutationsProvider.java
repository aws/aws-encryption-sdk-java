package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations;

import com.amazonaws.crypto.examples.mpl_mutation_examples.Constants;
import com.amazonaws.crypto.examples.mpl_mutation_examples.DdbHelper;
import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.AdminProvider;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.model.AwsKms;
import software.amazon.cryptography.keystoreadmin.KeyStoreAdmin;
import software.amazon.cryptography.keystoreadmin.model.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

public class MutationsProvider {

  public static String mutatedItemsToString(
    List<MutatedBranchKeyItem> mutatedItems
  ) {
    return mutatedItems
      .stream()
      .map(item -> String.format("%s : %s", item.ItemType(), item.Description())
      )
      .collect(Collectors.joining(",\n"));
  }

  public static Mutations defaultMutation(
    @Nonnull final String terminalKmsArn
  ) {
    HashMap<String, String> terminalEC = new HashMap<>(2, 1);
    terminalEC.put("Robbie", "is a dog.");
    return Mutations
      .builder()
      .TerminalEncryptionContext(terminalEC)
      .TerminalKmsArn(terminalKmsArn)
      .build();
  }

  public static SystemKey KmsSystemKey() {
    return KmsSystemKey(Fixtures.KSA_SYSTEM_KEY);
  }

  public static SystemKey KmsSystemKey(@Nonnull final String systemKeyArn) {
    return KmsSystemKey(systemKeyArn, null, null);
  }

  public static SystemKey KmsSystemKey(
    @Nonnull final String systemKeyArn,
    @Nullable KmsClient systemKeyKmsClient,
    @Nullable List<String> systemKeyGrantTokens
  ) {
    final List<String> tempList = systemKeyGrantTokens == null
      ? Collections.emptyList()
      : systemKeyGrantTokens;
    final KmsClient tempKms = systemKeyKmsClient == null
      ? AdminProvider.kms(null)
      : systemKeyKmsClient;
    final AwsKms tempAws = AwsKms
      .builder()
      .kmsClient(tempKms)
      .grantTokens(tempList)
      .build();
    return SystemKey
      .builder()
      .kmsSymmetricEncryption(
        KmsSymmetricEncryption
          .builder()
          .AwsKms(tempAws)
          .KmsArn(systemKeyArn)
          .build()
      )
      .build();
  }

  public static SystemKey TrustStorage() {
    return SystemKey
      .builder()
      .trustStorage(TrustStorage.builder().build())
      .build();
  }

  public static void workMutation(
    String branchKeyId,
    SystemKey systemKey,
    MutationToken token,
    KeyManagementStrategy strategy,
    KeyStoreAdmin admin,
    short limitLoop
  ) {
    boolean done = false;

    while (!done) {
      ApplyMutationResult result = workPage(
        branchKeyId,
        systemKey,
        token,
        strategy,
        admin,
        99
      );

      GetItemResponse mIndexRes = DdbHelper.getKeyStoreDdbItem(
              branchKeyId,
              Constants.TYPE_MUTATION_INDEX,
              Fixtures.TEST_KEYSTORE_NAME,
              Fixtures.ddbClientWest2
      );

      System.out.println(mIndexRes.item());

      if (result.ContinueMutation() != null) {
        token = result.ContinueMutation();
      }
      if (result.CompleteMutation() != null) {
        done = true;
      }
      if (limitLoop == 0) {
        throw new RuntimeException("Mutation not completed within limit!");
      }
      limitLoop--;
    }
  }

  static ApplyMutationResult workPage(
    String branchKeyId,
    SystemKey systemKey,
    MutationToken token,
    KeyManagementStrategy strategy,
    KeyStoreAdmin admin,
    Integer pageSize
  ) {
    ApplyMutationInput applyInput = ApplyMutationInput
      .builder()
      .MutationToken(token)
      .PageSize(pageSize)
      .Strategy(strategy)
      .SystemKey(systemKey)
      .build();
    ApplyMutationOutput applyOutput = admin.ApplyMutation(applyInput);
    ApplyMutationResult result = applyOutput.MutationResult();

    System.out.println(
      "ApplyLogs: " +
      branchKeyId +
      " items: \n" +
      mutatedItemsToString(applyOutput.MutatedBranchKeyItems())
    );
    return result;
  }

  static MutationToken executeInitialize(
    String branchKeyId,
    KeyStoreAdmin admin,
    InitializeMutationInput initInput,
    String logPrefix
  ) {
    InitializeMutationOutput initOutput = admin.InitializeMutation(initInput);
    MutationToken token = initOutput.MutationToken();
    System.out.println(
      logPrefix +
      ": " +
      "\nFlag: " +
      initOutput.InitializeMutationFlag().toString() +
      "\nIdentifier: " +
      branchKeyId +
      "\nitems: \n" +
      mutatedItemsToString(initOutput.MutatedBranchKeyItems())
    );
    return token;
  }

  /**
   * In some very advanced cases, it may be helpful to reset the Mutation Index.
   * This can be done by deleting the Mutation Index
   */
  static void resetMutationIndex(
    @Nonnull String branchKeyId,
    @Nonnull InitializeMutationInput initInput,
    @Nullable String physicalName,
    @Nullable String logicalName,
    @Nullable KeyStoreAdmin admin,
    @Nullable DynamoDbClient dynamoDbClient
  ) {
    final String _physicalName = physicalName == null
      ? Fixtures.TEST_KEYSTORE_NAME
      : physicalName;
    final String _logicalName = logicalName == null
      ? Fixtures.TEST_LOGICAL_KEYSTORE_NAME
      : logicalName;
    final DynamoDbClient _dynamoDbClient = dynamoDbClient == null
      ? Fixtures.ddbClientWest2
      : dynamoDbClient;
    final KeyStoreAdmin _admin = admin == null
      ? AdminProvider.admin(_physicalName, _logicalName, _dynamoDbClient)
      : admin;
    // If we want to restart the Mutation from the beginning, we delete the Index.
    DdbHelper.deleteKeyStoreDdbItem(
      branchKeyId,
      "branch:MUTATION_INDEX",
      _physicalName,
      _dynamoDbClient,
      false
    );
    // But if we deleted the index, we do need to call Initialize again
    MutationsProvider.executeInitialize(
      branchKeyId,
      _admin,
      initInput,
      "Restart Logs"
    );
    System.out.println(
      "\nDeletion of Index and subsequent call to Initialize reset the pageIndex: " +
      branchKeyId +
      "\n"
    );
  }
}
