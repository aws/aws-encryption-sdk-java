package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations;

import com.amazonaws.crypto.examples.mpl_mutation_examples.DdbHelper;
import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.AdminProvider;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.CreateKeyExample;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.KeyStoreProvider;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.ValidateKeyStoreItem;
import org.testng.Assert;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystoreadmin.KeyStoreAdmin;
import software.amazon.cryptography.keystoreadmin.model.InitializeMutationInput;
import software.amazon.cryptography.keystoreadmin.model.KeyManagementStrategy;
import software.amazon.cryptography.keystoreadmin.model.MutationToken;
import software.amazon.cryptography.keystoreadmin.model.SystemKey;

import java.util.List;
import java.util.Map;

import static com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations.MutationsProvider.executeInitialize;

public class DoNotVersionTest {

  static final String testPrefix = "initialize-mutation-do-not-version-java-";

  @Test
  public void DoNotVersion() {
    final KeyStoreAdmin admin = AdminProvider.admin();
    String branchKeyId = testPrefix + java.util.UUID.randomUUID().toString();
    Assert.assertEquals(
      branchKeyId,
      CreateKeyExample.CreateKey(Fixtures.KEYSTORE_KMS_ARN, branchKeyId, admin),
      "Creation of test BK failed."
    );
    SystemKey systemKey = MutationsProvider.KmsSystemKey();
    KeyManagementStrategy strategy = AdminProvider.strategy(
      Fixtures.kmsClientWest2
    );
    InitializeMutationInput initInput = InitializeMutationInput
      .builder()
      .Mutations(
        MutationsProvider.defaultMutation(Fixtures.POSTAL_HORN_KEY_ARN)
      )
      .Identifier(branchKeyId)
      .DoNotVersion(true)
      .SystemKey(systemKey)
      .Strategy(strategy)
      .build();

    MutationToken token = executeInitialize(
      branchKeyId,
      admin,
      initInput,
      "InitLogs"
    );

    MutationsProvider.workMutation(
      branchKeyId,
      systemKey,
      token,
      strategy,
      admin,
      (short) 10
    );
    final KeyStore keyStore = KeyStoreProvider.keyStore(
      Fixtures.POSTAL_HORN_KEY_ARN
    );
    ValidateKeyStoreItem.ValidateBranchKey(branchKeyId, keyStore);
    final List<Map<String, AttributeValue>> allBKItems =
      DdbHelper.QueryForAllBkItemsDDBKeys(branchKeyId, null, null, null);
    Assert.assertEquals(allBKItems.size(), 3, "Incorrect number of BK items.");
    DdbHelper.DeleteAllBkKeys(allBKItems, null, null);
  }
}
