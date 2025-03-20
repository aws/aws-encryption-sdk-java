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
import org.junit.Test;
import org.testng.Assert;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.AwsKms;
import software.amazon.cryptography.keystoreadmin.KeyStoreAdmin;
import software.amazon.cryptography.keystoreadmin.model.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations.MutationsProvider.mutatedItemsToString;

public class ExampleTests {

  @Test
  public void testMutationsProviderToGetLastModifiedTime() throws Exception {
    // Create a Branch Key & at-least 10 `DECRYPT_ONLY` versions
    String branchKeyId = CreateKeyExample.CreateKeyAndVersions(
            Fixtures.KEYSTORE_KMS_ARN,
            null,
            AdminProvider.admin(),
            5);
    System.out.println("\nCreated Branch Key: " + branchKeyId);


    branchKeyId = MutationExample.End2EndWithLastModifiedTime(Fixtures.POSTAL_HORN_KEY_ARN,
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

    // Delete Branch key after test
    DdbHelper.DeleteBranchKey(
            branchKeyId,
            Fixtures.TEST_KEYSTORE_NAME,
            "1",
            null
    );

  }

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
    System.out.println("\nVersioned Branch Key 1010: " + branchKeyId + "\n");
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

  }

  @Test
  public void CreateBranchKey() {
    String branchKeyId = CreateKeyExample.CreateKeyAndVersions(
            Fixtures.KEYSTORE_KMS_ARN,
            "mpl-branch-key-test-for-last-modified-time",
            AdminProvider.admin(),
            4
    );

    System.out.println("\nCreated Branch Key: " + branchKeyId);
    System.out.println("Versioned Branch Key " + 10 + " times");
  }

  @Test
  public void PrintSHA256Hash() throws NoSuchAlgorithmException {
    String active = "AQICAHhTIzkciiF5TDB8qaCjctFmv6Dx+4yjarauOA4MtH0jwgHgwh/iC3dWDadxz6DJBekSAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM6HCAYQ2SmRhiTMldAgEQgDvTJxZLK0x3fUIFPliDVUlWp58NuGNcGy8CjayK8VRd11QoU+ckf/5FtSOusURYvdCvfhmWWeOKDMnxaA==";
    String beacon = "AQIBAHhTIzkciiF5TDB8qaCjctFmv6Dx+4yjarauOA4MtH0jwgGEoCrxyNczEHZB290+ziusAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM68gXNs7A7rI7k/GNAgEQgDvp5SIwWA+G4ldPJophl1lnLksX713Mesvb8ns7HSeB4wOnBbubVY5K00om3eyGHept1/nARG/6/K3ptQ==";
    String version = "branch:version:8ba1a979-17fe-40d4-afe4-c920173de5be";

    byte[] decodedBytes = Base64.getDecoder().decode(active);
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(new byte[]{ 35, -17, 13, -58, -98, 71, -36, 32, 16, -44, -124, -66, -99, -90, -112, -115, 26, -18, -91, -24, 42, -38, -8, -127, 89, 66, -114, -60, 29, -26, 97, 70 });
    String decodedString = Base64.getEncoder().encodeToString(hash);

    byte[] beaconBytes = Base64.getDecoder().decode(beacon);
    byte[] beaconDigest = digest.digest(beaconBytes);
    String beaconString = Base64.getEncoder().encodeToString(beaconDigest);

    String invalidString = "\u0007";
    System.out.println(invalidString);
    byte[] invalidDigestBytes = invalidString.getBytes(StandardCharsets.UTF_8);
    String invalidDigestString = new String(invalidDigestBytes, StandardCharsets.UTF_8);
    System.out.println(invalidDigestString);

    version = version.split(":")[2];

    System.out.printf("\"branchKeyVersion\uD800\uDC02\": \"%s\",%n",version);
    System.out.printf("\"branchKey\": \"%s\",%n",decodedString);
    System.out.printf("\"beaconKey\": \"%s\"%n",beaconString);
  }

  @Test
  public void DeleteBranchKey() {
    String branchKeyId = "mpl-branch-key-test-for-last-modified-time";
    DdbHelper.DeleteBranchKey(
            branchKeyId,
            Fixtures.TEST_KEYSTORE_NAME,
            "1",
            null);
  }

  @Test
  public void MutateWithoutLastModifiedFIeld () {
    String branchKeyId = "mpl-branch-key-test-for-last-modified-time";

    System.out.println("\nCreated Branch Key: " + branchKeyId);
    System.out.println("Versioned Branch Key " + 5 + " times");

    String kmsKeyArnTerminal = Fixtures.KEYSTORE_KMS_ARN;
    KeyManagementStrategy strategy = AdminProvider.strategy(Fixtures.kmsClientWest2);
    SystemKey systemKey = MutationsProvider.KmsSystemKey();
    KeyStoreAdmin admin = AdminProvider.admin();

    final KeyManagementStrategy _strategy = AdminProvider.strategy(Fixtures.kmsClientWest2) == null
            ? AdminProvider.strategy(null)
            : strategy;
    final SystemKey _systemKey = systemKey == null
            ? MutationsProvider.KmsSystemKey()
            : systemKey;
    final KeyStoreAdmin _admin = admin == null ? AdminProvider.admin() : admin;

    System.out.println("BranchKey ID to mutate: " + branchKeyId);
    Mutations mutations = MutationsProvider.defaultMutation(kmsKeyArnTerminal);

    // INITIALIZE MUTATION
    InitializeMutationInput initInput = InitializeMutationInput
            .builder()
            .Mutations(mutations)
            .Identifier(branchKeyId)
//            .DoNotVersion(true)
            .Strategy(_strategy)
            .SystemKey(_systemKey)
            .build();
    InitializeMutationOutput initOutput = _admin.InitializeMutation(initInput);
//
    // Obtain a mutation token
    MutationToken token = initOutput.MutationToken();
    System.out.println(
            "Init Logs Before Adding Modified Time" +
                    ": " +
                    "\nFlag: " +
                    initOutput.InitializeMutationFlag().toString() +
                    "\nIdentifier: " +
                    branchKeyId +
                    "\nitems: \n" +
                    mutatedItemsToString(initOutput.MutatedBranchKeyItems())
    );

    // APPLY A PAGE OF MUTATION
    ApplyMutationInput applyInput = ApplyMutationInput
            .builder()
            .MutationToken(token)
            .PageSize(1)
            .Strategy(_strategy)
            .SystemKey(_systemKey)
            .build();
    ApplyMutationOutput applyOutput = _admin.ApplyMutation(applyInput);
    ApplyMutationResult result = applyOutput.MutationResult();

    System.out.println("ApplyLogs for Before Adding Modified Time: " + branchKeyId + ":\nMutated Items: "
            + mutatedItemsToString(applyOutput.MutatedBranchKeyItems()));
  }

  @Test
  public void ResumeAfterUpgradingToLastModifiedTime() {
    String branchKeyId = "mpl-branch-key-test-for-last-modified-time";

    String kmsKeyArnTerminal = Fixtures.KEYSTORE_KMS_ARN;
    KeyManagementStrategy strategy = AdminProvider.strategy(Fixtures.kmsClientWest2);
    SystemKey systemKey = MutationsProvider.KmsSystemKey();
    KeyStoreAdmin admin = AdminProvider.admin();

    final KeyManagementStrategy _strategy = AdminProvider.strategy(Fixtures.kmsClientWest2) == null
            ? AdminProvider.strategy(null)
            : strategy;
    final SystemKey _systemKey = systemKey == null
            ? MutationsProvider.KmsSystemKey()
            : systemKey;
    final KeyStoreAdmin _admin = admin == null ? AdminProvider.admin() : admin;

    System.out.println("BranchKey ID to mutate: " + branchKeyId);
    Mutations mutations = MutationsProvider.defaultMutation(kmsKeyArnTerminal);

    // INITIALIZE MUTATION
    InitializeMutationInput initInput = InitializeMutationInput
            .builder()
            .Mutations(mutations)
            .Identifier(branchKeyId)
            .DoNotVersion(true)
            .Strategy(_strategy)
            .SystemKey(_systemKey)
            .build();
    InitializeMutationOutput initOutput = _admin.InitializeMutation(initInput);
    MutationToken token = initOutput.MutationToken();

    System.out.println(
            "\n\nInit Logs After Adding Modified Time" +
                    ": " +
                    "\nFlag: " +
                    initOutput.InitializeMutationFlag().toString() +
                    "\nIdentifier: " +
                    branchKeyId +
                    "\nitems: \n" +
                    mutatedItemsToString(initOutput.MutatedBranchKeyItems()) +
                            "\nLast Modified Time: "
    + initOutput.LastModifiedTime()
    );

    // Describe Mutation
    DescribeMutationOutput descOutput = _admin.DescribeMutation(DescribeMutationInput.builder()
            .Identifier(branchKeyId).build());

    System.out.println("\n\nDescribeLogs: " + descOutput.MutationInFlight().Yes().LastModifiedTime());

    // Assert last modified time is same for both operations
//    assert initOutput.LastModifiedTime().equals(descOutput.MutationInFlight().Yes().LastModifidTime());

    ApplyMutationOutput applyOutput;

//    do {
      // APPLY A PAGE OF MUTATION
      ApplyMutationInput applyInput = ApplyMutationInput
              .builder()
              .MutationToken(token)
              .PageSize(1)
              .Strategy(_strategy)
              .SystemKey(_systemKey)
              .build();
      applyOutput = _admin.ApplyMutation(applyInput);
      if (applyOutput.MutationResult().ContinueMutation() != null) {
        token = applyOutput.MutationResult().ContinueMutation();
      }
      System.out.println("\n\nApplyLogs for After Adding Modified Time -> " + branchKeyId + ":\nMutated Items: "
              + mutatedItemsToString(applyOutput.MutatedBranchKeyItems()));
      System.out.println("Last Modified Time: "
              + applyOutput.LastModifiedTime()
      );
//    } while (applyOutput.MutationResult().CompleteMutation() == null);
  }

  @Test
  public void AtomicMutationsTesting() {
    String branchKeyId = "mpl-branch-key-test-for-last-modified-time";

    String kmsKeyArnTerminal = Fixtures.KEYSTORE_KMS_ARN;
    KeyManagementStrategy strategy = AdminProvider.strategy(Fixtures.kmsClientWest2);
    SystemKey systemKey = MutationsProvider.TrustStorage();
    KeyStoreAdmin admin = AdminProvider.admin();

    final KeyManagementStrategy _strategy = AdminProvider.strategy(Fixtures.kmsClientWest2) == null
            ? AdminProvider.strategy(null)
            : strategy;
    final SystemKey _systemKey = systemKey == null
            ? MutationsProvider.KmsSystemKey()
            : systemKey;
    final KeyStoreAdmin _admin = admin == null ? AdminProvider.admin() : admin;

    System.out.println("BranchKey ID to mutate: " + branchKeyId);
    Mutations mutations = MutationsProvider.defaultMutation(kmsKeyArnTerminal);

    // INITIALIZE MUTATION
    InitializeMutationInput initInput = InitializeMutationInput
            .builder()
            .Mutations(mutations)
            .Identifier(branchKeyId)
            .DoNotVersion(true)
            .Strategy(_strategy)
            .SystemKey(_systemKey)
            .build();
    InitializeMutationOutput initOutput = _admin.InitializeMutation(initInput);
    MutationToken token = initOutput.MutationToken();

    System.out.println(
            "\n\nInit Logs After Adding Modified Time" +
                    ": " +
                    "\nFlag: " +
                    initOutput.InitializeMutationFlag().toString() +
                    "\nIdentifier: " +
                    branchKeyId +
                    "\nitems: \n" +
                    mutatedItemsToString(initOutput.MutatedBranchKeyItems()) +
                    "\nLast Modified Time: "
//                    + initOutput.LastModifiedTime()
    );
//
//    // Describe Mutation
//    DescribeMutationOutput descOutput = _admin.DescribeMutation(DescribeMutationInput.builder()
//            .Identifier(branchKeyId).build());
//
//    System.out.println("\n\nDescribeLogs: " + descOutput.MutationInFlight().Yes().LastModifiedTime());
//
//    // Assert last modified time is same for both operations
//    assert initOutput.LastModifiedTime().equals(descOutput.MutationInFlight().Yes().LastModifiedTime());
//
//    ApplyMutationOutput applyOutput;
//
//    do {
//      // APPLY A PAGE OF MUTATION
//      ApplyMutationInput applyInput = ApplyMutationInput
//              .builder()
//              .MutationToken(token)
//              .PageSize(1)
//              .Strategy(_strategy)
//              .SystemKey(_systemKey)
//              .build();
//      applyOutput = _admin.ApplyMutation(applyInput);
//      if (applyOutput.MutationResult().ContinueMutation() != null) {
//        token = applyOutput.MutationResult().ContinueMutation();
//      }
//      System.out.println("\n\nApplyLogs for After Adding Modified Time -> " + branchKeyId + ":\nMutated Items: "
//              + mutatedItemsToString(initOutput.MutatedBranchKeyItems()));
//      System.out.println("Last Modified Time: "
//              + applyOutput.LastModifiedTime()
//      );
//    } while (applyOutput.MutationResult().CompleteMutation() == null);
  }


//  @Test
//  public void End2EndResumeTest() {
//    String branchKeyId = CreateKeyExample.CreateKeyAndVersions(
//            Fixtures.KEYSTORE_KMS_ARN,
//            null,
//            AdminProvider.admin(),
//            5
//    );
//    System.out.println("\nCreated Branch Key: " + branchKeyId);
//    System.out.println("Versioned Branch Key " + 5 + " times");
//
//
//    branchKeyId = MutationResumeExample.Resume2EndLastModifiedField(
//            branchKeyId,
//            Fixtures.KEYSTORE_KMS_ARN,
//            AdminProvider.strategy(Fixtures.kmsClientWest2),
//            MutationsProvider.TrustStorage(),
//            AdminProvider.admin()
//    );
//    System.out.println(
//            "\nMutated Branch Key with Resume: " +
//                    branchKeyId +
//                    " to KMS ARN: " +
//                    Fixtures.KEYSTORE_KMS_ARN +
//                    "\n"
//    );
//    GetItemResponse mCommitmentRes;
//	  mCommitmentRes = DdbHelper.getKeyStoreDdbItem(
//	          branchKeyId,
//	          Constants.TYPE_MUTATION_COMMITMENT,
//	          Fixtures.TEST_KEYSTORE_NAME,
//	          Fixtures.ddbClientWest2
//	  );
//	  Assert.assertFalse(
//            mCommitmentRes.hasItem(),
//            Constants.TYPE_MUTATION_COMMITMENT + " was not deleted!"
//    );
//    GetItemResponse mIndexRes = DdbHelper.getKeyStoreDdbItem(
//            branchKeyId,
//            Constants.TYPE_MUTATION_INDEX,
//            Fixtures.TEST_KEYSTORE_NAME,
//            Fixtures.ddbClientWest2
//    );
//    Assert.assertFalse(
//            mIndexRes.hasItem(),
//            Constants.TYPE_MUTATION_INDEX + " was not deleted!"
//    );
//    KeyStore keyStoreKS = KeyStoreProvider.keyStore(Fixtures.KEYSTORE_KMS_ARN);
//    ValidateKeyStoreItem.ValidateBranchKey(branchKeyId, keyStoreKS);
//    DdbHelper.DeleteBranchKey(
//            branchKeyId,
//            Fixtures.TEST_KEYSTORE_NAME,
//            "1",
//            null
//    );
//  }

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
