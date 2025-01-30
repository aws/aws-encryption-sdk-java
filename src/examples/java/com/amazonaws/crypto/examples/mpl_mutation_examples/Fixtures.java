// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.crypto.examples.mpl_mutation_examples;

import java.time.Duration;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;

public class Fixtures {

  public static final String TEST_KEYSTORE_NAME = "KeyStoreDdbTable";
  public static final String TEST_LOGICAL_KEYSTORE_NAME = "KeyStoreDdbTable";

  // KMS Keys
  // HierarchicalGitHubKMSKeyIDTwo
  public static final String POSTAL_HORN_KEY_ARN =
    "arn:aws:kms:us-west-2:370957321024:key/bc127593-f7da-452c-a1f3-cd34c46f81f8";
  // HierarchicalGitHubKMSKeyID
  public static final String KEYSTORE_KMS_ARN =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
  public static final String MRK_ARN_EAST =
    "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
  public static final String MRK_ARN_WEST =
    "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
  // Key MUST NOT exist in ap-south-2
  public static final String MRK_ARN_AP =
    "arn:aws:kms:ap-south-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
  public static final String KSA_SYSTEM_KEY =
    "arn:aws:kms:us-west-2:370957321024:key/6613e250-b2e7-4c4c-a54e-2b241f837242";

  // IAM Roles
  public static final String LIMITED_KMS_ACCESS_IAM_ROLE =
    "arn:aws:iam::370957321024:role/GitHub-CI-MPL-Limited-KMS-us-west-2";
  // ^ can not access: MRK_ARN_EAST, MRK_ARN_WEST, and MRK_ARN_AP
  public static final String NO_KMS_ACCESS_IAM_ROLE =
    "arn:aws:iam::370957321024:role/GitHub-CI-MPL-No-KMS-us-west-2";
  public static final String KMS_POSTAL_HORN_ONLY =
    "arn:aws:iam::370957321024:role/Restricted-KMS-HKey-Two-Only";
  public static final String KMS_KEYSTORE_ONLY =
    "arn:aws:iam::370957321024:role/Restricted-KMS-HKey-One-Only";

  public static final AwsCredentialsProvider defaultCreds =
    DefaultCredentialsProvider.create();
  public static final SdkHttpClient httpClient = ApacheHttpClient
    .builder()
    .connectionTimeToLive(Duration.ofSeconds(5))
    .build();
  public static final DynamoDbClient ddbClientWest2 = DynamoDbClient
    .builder()
    .httpClient(httpClient)
    .credentialsProvider(defaultCreds)
    .region(Region.US_WEST_2)
    .build();
  public static final KmsClient kmsClientWest2 = KmsClient
    .builder()
    .httpClient(httpClient)
    .credentialsProvider(defaultCreds)
    .region(Region.US_WEST_2)
    .build();
  public static final KmsClient kmsClientEast1 = KmsClient
    .builder()
    .httpClient(httpClient)
    .credentialsProvider(defaultCreds)
    .region(Region.US_EAST_1)
    .build();
  public static final KmsClient denyMrkKmsClient = KmsClient
    .builder()
    .credentialsProvider(
      CredentialUtils.credsForRole(
        Fixtures.LIMITED_KMS_ACCESS_IAM_ROLE,
        "java-mpl-examples",
        Region.US_WEST_2,
        Fixtures.httpClient,
        Fixtures.defaultCreds
      )
    )
    .region(Region.US_WEST_2)
    .httpClient(Fixtures.httpClient)
    .build();
  public static final KmsClient postalHornOnlyKmsClient = KmsClient
    .builder()
    .credentialsProvider(
      CredentialUtils.credsForRole(
        Fixtures.KMS_POSTAL_HORN_ONLY,
        "java-mpl-examples",
        Region.US_WEST_2,
        Fixtures.httpClient,
        Fixtures.defaultCreds
      )
    )
    .region(Region.US_WEST_2)
    .httpClient(Fixtures.httpClient)
    .build();
  public static final KmsClient keyStoreOnlyKmsClient = KmsClient
    .builder()
    .credentialsProvider(
      CredentialUtils.credsForRole(
        Fixtures.KMS_KEYSTORE_ONLY,
        "java-mpl-examples",
        Region.US_WEST_2,
        Fixtures.httpClient,
        Fixtures.defaultCreds
      )
    )
    .region(Region.US_WEST_2)
    .httpClient(Fixtures.httpClient)
    .build();
}
