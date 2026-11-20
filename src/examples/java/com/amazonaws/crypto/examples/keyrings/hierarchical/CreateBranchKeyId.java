// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings.hierarchical;

import static com.amazonaws.encryptionsdk.kms.KMSTestFixtures.TEST_KEYSTORE_KMS_KEY_ID;
import static com.amazonaws.encryptionsdk.kms.KMSTestFixtures.TEST_KEYSTORE_NAME;
import static com.amazonaws.encryptionsdk.kms.KMSTestFixtures.TEST_LOGICAL_KEYSTORE_NAME;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.keystore.model.CreateKeyOutput;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;

public class CreateBranchKeyId {
  public static String createBranchKeyId() {
    // Create an AWS KMS Configuration to use with your KeyStore.
    // The KMS Configuration MUST have the right access to the resources in the KeyStore.
    final KMSConfiguration kmsConfig =
        KMSConfiguration.builder().kmsKeyArn(TEST_KEYSTORE_KMS_KEY_ID).build();

    // Configure your KeyStore resource.
    //    This SHOULD be the same configuration that you used
    //    to initially create and populate your KeyStore.
    final KeyStoreConfig keystoreConfig =
        KeyStoreConfig.builder()
            .ddbClient(DynamoDbClient.create())
            .ddbTableName(TEST_KEYSTORE_NAME)
            .logicalKeyStoreName(TEST_LOGICAL_KEYSTORE_NAME)
            .kmsClient(KmsClient.create())
            .kmsConfiguration(kmsConfig)
            .build();

    // Create a KeyStore
    final KeyStore keystore = KeyStore.builder().KeyStoreConfig(keystoreConfig).build();

    // Create a branch key identifier with the AWS KMS Key configured in the KeyStore Configuration.
    final CreateKeyOutput branchKeyId = keystore.CreateKey(CreateKeyInput.builder().build());

    return branchKeyId.branchKeyIdentifier();
  }
}
