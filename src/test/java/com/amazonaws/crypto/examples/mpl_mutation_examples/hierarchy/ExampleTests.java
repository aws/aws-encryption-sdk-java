// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy;

import com.amazonaws.crypto.examples.mpl_mutation_examples.Constants;
import com.amazonaws.crypto.examples.mpl_mutation_examples.DdbHelper;
import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations.MutationDecryptEncryptExample;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations.MutationExample;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations.MutationResumeExample;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations.MutationsProvider;
import org.testng.Assert;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.AwsKms;

public class ExampleTests {

  @Test
  public void End2EndReEncryptTest() {
    String branchKeyId = CreateKeyExample.CreateKey(
      Fixtures.KEYSTORE_KMS_ARN,
      null,
      AdminProvider.admin()
    );
    System.out.println("\nCreated Branch Key: " + branchKeyId);
    branchKeyId =
      MutationExample.End2End(
        Fixtures.POSTAL_HORN_KEY_ARN,
        branchKeyId,
        MutationsProvider.TrustStorage(),
        AdminProvider.admin()
      );
    System.out.println(
      "\nMutated Branch Key: " +
      branchKeyId +
      " to KMS ARN: " +
      Fixtures.POSTAL_HORN_KEY_ARN +
      "\n"
    );
    KeyStore postalHornKS = KeyStoreProvider.keyStore(
      Fixtures.POSTAL_HORN_KEY_ARN
    );
    ValidateKeyStoreItem.ValidateBranchKey(branchKeyId, postalHornKS);
    branchKeyId =
      VersionKeyExample.VersionKey(
        Fixtures.POSTAL_HORN_KEY_ARN,
        branchKeyId,
        AdminProvider.admin()
      );
    branchKeyId =
      VersionKeyExample.VersionKey(
        Fixtures.POSTAL_HORN_KEY_ARN,
        branchKeyId,
        AdminProvider.admin()
      );
    System.out.println("\nVersioned Branch Key: " + branchKeyId + "\n");
    GetItemResponse mCommitmentRes = DdbHelper.getKeyStoreDdbItem(
      branchKeyId,
      Constants.TYPE_MUTATION_COMMITMENT,
      Fixtures.TEST_KEYSTORE_NAME,
      Fixtures.ddbClientWest2
    );
    Assert.assertFalse(
      mCommitmentRes.hasItem(),
      Constants.TYPE_MUTATION_COMMITMENT + " was not deleted!"
    );
    GetItemResponse mIndexRes = DdbHelper.getKeyStoreDdbItem(
      branchKeyId,
      Constants.TYPE_MUTATION_INDEX,
      Fixtures.TEST_KEYSTORE_NAME,
      Fixtures.ddbClientWest2
    );
    Assert.assertFalse(
      mIndexRes.hasItem(),
      Constants.TYPE_MUTATION_INDEX + " was not deleted!"
    );
    branchKeyId =
      MutationResumeExample.Resume2End(
        branchKeyId,
        Fixtures.KEYSTORE_KMS_ARN,
        AdminProvider.strategy(Fixtures.kmsClientWest2),
        MutationsProvider.TrustStorage(),
        AdminProvider.admin()
      );
    System.out.println(
      "\nMutated Branch Key with Resume: " +
      branchKeyId +
      " to KMS ARN: " +
      Fixtures.KEYSTORE_KMS_ARN +
      "\n"
    );
    mCommitmentRes =
      DdbHelper.getKeyStoreDdbItem(
        branchKeyId,
        Constants.TYPE_MUTATION_COMMITMENT,
        Fixtures.TEST_KEYSTORE_NAME,
        Fixtures.ddbClientWest2
      );
    Assert.assertFalse(
      mCommitmentRes.hasItem(),
      Constants.TYPE_MUTATION_COMMITMENT + " was not deleted!"
    );
    mIndexRes =
      DdbHelper.getKeyStoreDdbItem(
        branchKeyId,
        Constants.TYPE_MUTATION_INDEX,
        Fixtures.TEST_KEYSTORE_NAME,
        Fixtures.ddbClientWest2
      );
    Assert.assertFalse(
      mIndexRes.hasItem(),
      Constants.TYPE_MUTATION_INDEX + " was not deleted!"
    );
    KeyStore keyStoreKS = KeyStoreProvider.keyStore(Fixtures.KEYSTORE_KMS_ARN);
    ValidateKeyStoreItem.ValidateBranchKey(branchKeyId, keyStoreKS);
    DdbHelper.DeleteBranchKey(
      branchKeyId,
      Fixtures.TEST_KEYSTORE_NAME,
      "1",
      null
    );
  }

  @Test
  public void End2EndDecryptEncryptTest() {
    String branchKeyId = CreateKeyExample.CreateKey(
      Fixtures.KEYSTORE_KMS_ARN,
      null,
      AdminProvider.admin()
    );
    System.out.println("\nCreated Branch Key: " + branchKeyId);
    branchKeyId =
      MutationDecryptEncryptExample.End2End(
        branchKeyId,
        Fixtures.POSTAL_HORN_KEY_ARN,
        AwsKms.builder().kmsClient(Fixtures.keyStoreOnlyKmsClient).build(),
        AwsKms.builder().kmsClient(Fixtures.postalHornOnlyKmsClient).build(),
        MutationsProvider.KmsSystemKey(),
        AdminProvider.admin()
      );
    System.out.println(
      "\nMutated Branch Key: " +
      branchKeyId +
      " to KMS ARN: " +
      Fixtures.POSTAL_HORN_KEY_ARN +
      "\n"
    );
    GetItemResponse mCommitmentRes = DdbHelper.getKeyStoreDdbItem(
      branchKeyId,
      Constants.TYPE_MUTATION_COMMITMENT,
      Fixtures.TEST_KEYSTORE_NAME,
      Fixtures.ddbClientWest2
    );
    Assert.assertFalse(
      mCommitmentRes.hasItem(),
      Constants.TYPE_MUTATION_COMMITMENT + " was not deleted!"
    );
    GetItemResponse mIndexRes = DdbHelper.getKeyStoreDdbItem(
      branchKeyId,
      Constants.TYPE_MUTATION_INDEX,
      Fixtures.TEST_KEYSTORE_NAME,
      Fixtures.ddbClientWest2
    );
    Assert.assertFalse(
      mIndexRes.hasItem(),
      Constants.TYPE_MUTATION_INDEX + " was not deleted!"
    );
    KeyStore postalHornKS = KeyStoreProvider.keyStore(
      Fixtures.POSTAL_HORN_KEY_ARN
    );
    ValidateKeyStoreItem.ValidateBranchKey(branchKeyId, postalHornKS);
    branchKeyId =
      VersionKeyExample.VersionKey(
        Fixtures.POSTAL_HORN_KEY_ARN,
        branchKeyId,
        AdminProvider.admin()
      );
    branchKeyId =
      VersionKeyExample.VersionKey(
        Fixtures.POSTAL_HORN_KEY_ARN,
        branchKeyId,
        AdminProvider.admin()
      );
    System.out.println("\nVersioned Branch Key: " + branchKeyId + "\n");
    branchKeyId =
      MutationResumeExample.Resume2End(
        branchKeyId,
        Fixtures.KEYSTORE_KMS_ARN,
        AdminProvider.strategy(Fixtures.kmsClientWest2),
        MutationsProvider.TrustStorage(),
        AdminProvider.admin()
      );
    System.out.println(
      "\nMutated Branch Key with Resume: " +
      branchKeyId +
      " to KMS ARN: " +
      Fixtures.KEYSTORE_KMS_ARN +
      "\n"
    );
    mCommitmentRes =
      DdbHelper.getKeyStoreDdbItem(
        branchKeyId,
        Constants.TYPE_MUTATION_COMMITMENT,
        Fixtures.TEST_KEYSTORE_NAME,
        Fixtures.ddbClientWest2
      );
    Assert.assertFalse(
      mCommitmentRes.hasItem(),
      Constants.TYPE_MUTATION_COMMITMENT + " was not deleted!"
    );
    mIndexRes =
      DdbHelper.getKeyStoreDdbItem(
        branchKeyId,
        Constants.TYPE_MUTATION_INDEX,
        Fixtures.TEST_KEYSTORE_NAME,
        Fixtures.ddbClientWest2
      );
    Assert.assertFalse(
      mIndexRes.hasItem(),
      Constants.TYPE_MUTATION_INDEX + " was not deleted!"
    );
    KeyStore keyStoreKS = KeyStoreProvider.keyStore(Fixtures.KEYSTORE_KMS_ARN);
    ValidateKeyStoreItem.ValidateBranchKey(branchKeyId, keyStoreKS);
    DdbHelper.DeleteBranchKey(
      branchKeyId,
      Fixtures.TEST_KEYSTORE_NAME,
      "1",
      null
    );
  }
}
