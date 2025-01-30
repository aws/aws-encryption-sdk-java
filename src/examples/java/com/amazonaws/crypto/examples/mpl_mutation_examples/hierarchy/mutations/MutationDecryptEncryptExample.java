// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations;

import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.AdminProvider;
import software.amazon.cryptography.keystore.model.AwsKms;
import software.amazon.cryptography.keystoreadmin.KeyStoreAdmin;
import software.amazon.cryptography.keystoreadmin.model.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * See {@link MutationExample} for an explanation on Mutations.
 * Some use cases call for using different AWS Credentials when mutating
 * a Branch Key's KMS ARN.
 * If an agent only has access to a KMS ARN by assuming a particular IAM Role,
 * and that IAM Role only has access to one KMS ARN,
 * then the Key Store Admin's default ReEncrypt Strategy cannot
 * facilitate a Mutation of KMS ARN. <p>
 * For such scenarios,
 * the Decrypt Encrypt Strategy can be used. <p>
 * Note: <strong>The Decrypt Encrypt Strategy does not
 * solely use {@code kms:Encrypt} and {@code kms:Decrypt}.</strong>
 * But it does afford distinct AWS Credentials/KMS Clients
 * for the KMS requests.
 */
public class MutationDecryptEncryptExample {

  public static String End2End(
    @Nonnull String branchKeyId,
    @Nonnull String terminalKmsArn,
    @Nonnull AwsKms originalAwsKms,
    @Nonnull AwsKms terminalAwsKms,
    @Nonnull SystemKey systemKey,
    @Nullable KeyStoreAdmin admin
  ) {
    final KeyManagementStrategy strategy = KeyManagementStrategy
      .builder()
      .AwsKmsDecryptEncrypt(
        AwsKmsDecryptEncrypt
          .builder()
          // When creating items, the Encrypt KMS Client is used
          .encrypt(terminalAwsKms)
          // When validating or decrypting items in the original state,
          // the Decrypt KMS Client is used
          .decrypt(originalAwsKms)
          .build()
      )
      .build();

    Mutations mutations = MutationsProvider.defaultMutation(terminalKmsArn);
    final KeyStoreAdmin _admin = admin == null ? AdminProvider.admin() : admin;

    InitializeMutationInput initInput = InitializeMutationInput
      .builder()
      .Mutations(mutations)
      .Identifier(branchKeyId)
      .Strategy(strategy)
      .SystemKey(systemKey)
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
      systemKey,
      token,
      strategy,
      _admin,
      (short) 10
    );

    System.out.println("Done with Mutation: " + branchKeyId);

    return branchKeyId;
  }
}
