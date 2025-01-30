// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations;

import com.amazonaws.crypto.examples.mpl_mutation_examples.DdbHelper;
import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.AdminProvider;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.CreateKeyExample;
import software.amazon.cryptography.keystoreadmin.KeyStoreAdmin;
import software.amazon.cryptography.keystoreadmin.model.*;

import javax.annotation.Nullable;
import java.util.Objects;

import static com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations.MutationsProvider.executeInitialize;

/**
 * Mutations are complex asynchronous workflows.
 * The {@code DescribeMutation} operation can be used to
 * inspect the details of an in-flight Mutation.
 * It can also be used to check if a Mutation is in-flight at all,
 * or to retrieve the {@code MutationToken} for an in-flight Mutation.
 * The {@code MutationToken} can than be passed to {@code ApplyMutation}
 * to work or complete the Mutation.
 */
public class DescribeMutationExample {

  @Nullable
  public static DescribeMutationOutput Example(
    String branchKeyId,
    @Nullable KeyStoreAdmin admin
  ) {
    final KeyStoreAdmin _admin = admin == null ? AdminProvider.admin() : admin;
    DescribeMutationInput input = DescribeMutationInput
      .builder()
      .Identifier(branchKeyId)
      .build();
    
    DescribeMutationOutput output = _admin.DescribeMutation(input);
    
    // If there is no Mutation in-flight for the given Branch Key ID,
    // No will not be null
    if (output.MutationInFlight().No() != null) {
      System.out.println(
        "There is no mutation in flight for Branch Key ID: " + branchKeyId
      );
      return null;
    }
    // If there is a Mutation in-flight for the given Branch Key ID,
    // Yes will not be null
    if (output.MutationInFlight().Yes() != null) {
      // The Yes object holds a MutationDescription object
      MutationDescription description = output.MutationInFlight().Yes();
      MutationDetails mutation = description.MutationDetails();
      System.out.println(
        "There is a mutation in flight for Branch Key ID: " +
        branchKeyId +
        "\n It was started on: " +
        description.MutationDetails().CreateTime() +
        "\n The Input was: " +
        description.MutationDetails().Input()
      );
      
      
      
      // The Description object holds Details and the Token.
      System.out.println(
        "The Token to continue the Mutation is: " + description.MutationToken()
      );
      return output;
    }
    throw new RuntimeException("Key Store Admin returned nonsensical response");
  }

  public static MutationToken InitMutation(
    String branchKeyId,
    String kmsKeyArnTerminal,
    @Nullable SystemKey systemKey,
    @Nullable KeyManagementStrategy strategy,
    @Nullable KeyStoreAdmin admin
  ) {
    final SystemKey _systemKey = systemKey == null
      ? MutationsProvider.KmsSystemKey()
      : systemKey;
    final KeyManagementStrategy _strategy = strategy == null
      ? AdminProvider.strategy(null)
      : strategy;
    final KeyStoreAdmin _admin = admin == null ? AdminProvider.admin() : admin;

    InitializeMutationInput initInput = InitializeMutationInput
      .builder()
      .Mutations(MutationsProvider.defaultMutation(kmsKeyArnTerminal))
      .Identifier(branchKeyId)
      .Strategy(_strategy)
      .SystemKey(_systemKey)
      .build();

    MutationToken token = executeInitialize(
      branchKeyId,
      _admin,
      initInput,
      "InitLogs"
    );
    return token;
  }

  public static void CompleteExample(
    String kmsKeyArnOriginal,
    String kmsKeyArnTerminal,
    String branchKeyId,
    @Nullable SystemKey systemKey,
    @Nullable KeyManagementStrategy strategy,
    @Nullable KeyStoreAdmin admin
  ) {
    final SystemKey _systemKey = systemKey == null
      ? MutationsProvider.KmsSystemKey()
      : systemKey;
    final KeyManagementStrategy _strategy = strategy == null
      ? AdminProvider.strategy(null)
      : strategy;
    final KeyStoreAdmin _admin = admin == null ? AdminProvider.admin() : admin;

    CreateKeyExample.CreateKey(kmsKeyArnOriginal, branchKeyId, _admin);

    MutationToken fromInit = InitMutation(
      branchKeyId,
      kmsKeyArnTerminal,
      _systemKey,
      _strategy,
      _admin
    );

    DescribeMutationOutput describeRes = Example(branchKeyId, _admin);
    assert Objects.requireNonNull(describeRes).MutationInFlight().Yes() !=
    null : "No mutation in flight for Branch Key ID: " + branchKeyId;
    MutationToken fromDescribe = describeRes
      .MutationInFlight()
      .Yes()
      .MutationToken();
    assert fromDescribe != null;
    assert Objects.equals(fromInit.UUID(), fromDescribe.UUID());
    DdbHelper.DeleteBranchKey(
      branchKeyId,
      Fixtures.TEST_KEYSTORE_NAME,
      "1",
      null
    );
  }
}
