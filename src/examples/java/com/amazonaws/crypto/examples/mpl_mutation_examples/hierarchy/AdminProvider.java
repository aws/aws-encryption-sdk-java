// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy;

import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.model.AwsKms;
import software.amazon.cryptography.keystore.model.DynamoDBTable;
import software.amazon.cryptography.keystore.model.Storage;
import software.amazon.cryptography.keystoreadmin.KeyStoreAdmin;
import software.amazon.cryptography.keystoreadmin.model.AwsKmsDecryptEncrypt;
import software.amazon.cryptography.keystoreadmin.model.KeyManagementStrategy;
import software.amazon.cryptography.keystoreadmin.model.KeyStoreAdminConfig;

import javax.annotation.Nullable;

public class AdminProvider {

  public static KeyStoreAdmin admin(
    String physicalName,
    String logicalName,
    @Nullable DynamoDbClient dynamoDbClient
  ) {
    final DynamoDbClient _ddbClient = dynamoDB(dynamoDbClient);
    DynamoDBTable table = DynamoDBTable
      .builder()
      .ddbClient(_ddbClient)
      .ddbTableName(physicalName)
      .build();
    Storage storage = Storage.builder().ddb(table).build();

    KeyStoreAdminConfig config = KeyStoreAdminConfig
      .builder()
      .logicalKeyStoreName(logicalName)
      .storage(storage)
      .build();

    return KeyStoreAdmin.builder().KeyStoreAdminConfig(config).build();
  }

  public static KeyStoreAdmin admin() {
    return admin(
      Fixtures.TEST_KEYSTORE_NAME,
      Fixtures.TEST_LOGICAL_KEYSTORE_NAME,
      Fixtures.ddbClientWest2
    );
  }

  public static KeyManagementStrategy strategy(@Nullable KmsClient kmsClient) {
    return KeyManagementStrategy
      .builder()
      .AwsKmsReEncrypt(AwsKms.builder().kmsClient(kms(kmsClient)).build())
      .build();
  }

  public static KeyManagementStrategy decryptEncryptStrategy(
    @Nullable KmsClient decryptKmsClient,
    @Nullable KmsClient encryptKmsClient
  ) {
    decryptKmsClient = kms(decryptKmsClient);
    encryptKmsClient = kms(encryptKmsClient);

    return KeyManagementStrategy
      .builder()
      .AwsKmsDecryptEncrypt(
        AwsKmsDecryptEncrypt
          .builder()
          .decrypt(AwsKms.builder().kmsClient(decryptKmsClient).build())
          .encrypt(AwsKms.builder().kmsClient(encryptKmsClient).build())
          .build()
      )
      .build();
  }

  public static DynamoDbClient dynamoDB(
    @Nullable DynamoDbClient dynamoDbClient
  ) {
    return dynamoDbClient == null ? DynamoDbClient.create() : dynamoDbClient;
  }

  public static KmsClient kms(@Nullable KmsClient kmsClient) {
    return kmsClient == null ? KmsClient.create() : kmsClient;
  }
}
