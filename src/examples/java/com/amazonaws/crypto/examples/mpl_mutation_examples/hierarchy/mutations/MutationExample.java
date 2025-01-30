// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations;

import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.AdminProvider;
import software.amazon.cryptography.keystoreadmin.KeyStoreAdmin;
import software.amazon.cryptography.keystoreadmin.model.*;

import javax.annotation.Nullable;
import java.util.HashMap;

/**
 * A Branch Key can be Mutated via a Mutation.
 * Only certain elements of a Branch Key can be mutated:
 * <ul>
 *   <li>The Encryption Context</li>
 *   <li>The KMS ARN</li>
 * </ul>
 * Mutations are a workflow facilitated by the Key Store Admin class.
 * They are started by {@code InitializeMutation},
 * and then worked by {@code ApplyMutation}.
 * This division allows a change to be applied asynchronously
 * to all versions of a Branch Key,
 * even if there are hundreds of versions. <p>
 * Note: <Strong>It is a best practice to use KMS System Key when executing a mutation.</Strong>
 * See {@link MutationSystemKeyKMSExample} for details. <p>
 * {@code InitializeMutation} serializes the Mutation of a Branch Key,
 * persisting it to Key Store's Storage,
 * such that every {@code ApplyMutation} operation consistently applies
 * the same Mutation.
 * {@code InitializeMutation} and {@code ApplyMutation} also serialize
 * a "page Index" to storage;
 * think of this "page Index" as a bookmark;
 * it tells the library what is left to do.
 * {@code ApplyMutation} should be called until
 * it returns {@code CompleteMutation}. <p>
 * Note: <strong>A Mutation can lead to lock out of a Branch Key!</strong>
 * Access to a Branch Key is predicated on access to the KMS Key that protects
 * the Branch Key, constrained by the Encryption Context of the Branch Key
 * and the KMS Key Policy.
 * Changing (mutating) these attributes of a Branch Key changes these predicates;
 * agents that had access may lose access. <p>
 * Note: <strong>Mutations are asynchronous and should be completed.</strong>
 * See {@link ScanForInFlightMutations#ScanForInFlightMutations} for an example
 * utility to scan for in-complete Mutations.
 * An in-complete Mutation leaves a Branch Key in a mixed state.
 * Presumably, both states are safe, but it is a Best Practice to
 * keep a Branch Key in one consistent state.
 * Otherwise, reasoning about the Security domain of the Branch Key is difficult.
 * For this reason,
 * AWS Crypto Tools recommends completing Mutations as quickly as possible,
 * using robust workflow solutions such as SQS and Lambda,
 * along with a Dead Letter Queue,
 * to ensure any transient failure does not block the eventual completion of
 * a Mutation.
 */
public class MutationExample {

  public static String End2End(
    String kmsKeyArnTerminal,
    String branchKeyId,
    @Nullable SystemKey systemKey,
    @Nullable KeyStoreAdmin admin
  ) {
    final SystemKey _systemKey = systemKey == null
      ? MutationsProvider.KmsSystemKey()
      : systemKey;
    final KeyStoreAdmin _admin = admin == null ? AdminProvider.admin() : admin;
    final KeyManagementStrategy strategy = AdminProvider.strategy(null);

    System.out.println("BranchKey ID to mutate: " + branchKeyId);
    HashMap<String, String> terminalEC = new HashMap<>();
    terminalEC.put("Robbie", "is a dog.");
    Mutations mutations = Mutations
      .builder()
      .TerminalEncryptionContext(terminalEC)
      .TerminalKmsArn(kmsKeyArnTerminal)
      .build();

    InitializeMutationInput initInput = InitializeMutationInput
      .builder()
      .Mutations(mutations)
      .Identifier(branchKeyId)
      .Strategy(strategy)
      .SystemKey(_systemKey)
      .build();

    InitializeMutationOutput initOutput = _admin.InitializeMutation(initInput);

    MutationToken token = initOutput.MutationToken();
    System.out.println(
      "InitLogs: " +
      branchKeyId +
      " items: \n" +
      MutationsProvider.mutatedItemsToString(initOutput.MutatedBranchKeyItems())
    );
    MutationsProvider.workMutation(
      branchKeyId,
      _systemKey,
      token,
      strategy,
      _admin,
      (short) 10
    );

    System.out.println("Done with Mutation: " + branchKeyId);

    return branchKeyId;
  }
}
