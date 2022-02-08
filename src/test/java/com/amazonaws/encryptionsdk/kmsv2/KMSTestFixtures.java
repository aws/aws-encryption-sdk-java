// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kmsv2;

public final class KMSTestFixtures {
  private KMSTestFixtures() {
    throw new UnsupportedOperationException(
        "This class exists to hold static constants and cannot be instantiated.");
  }

  /**
   * These special test keys have been configured to allow Encrypt, Decrypt, and GenerateDataKey
   * operations from any AWS principal and should be used when adding new KMS tests.
   *
   * <p>This should go without saying, but never use these keys for production purposes (as anyone
   * in the world can decrypt data encrypted using them).
   */
  public static final String US_WEST_2_KEY_ID =
      "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

  public static final String EU_CENTRAL_1_KEY_ID =
      "arn:aws:kms:eu-central-1:658956600833:key/75414c93-5285-4b57-99c9-30c1cf0a22c2";
  public static final String US_EAST_1_MULTI_REGION_KEY_ID =
      "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
  public static final String US_WEST_2_MULTI_REGION_KEY_ID =
      "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
  public static final String ACCOUNT_ID = "658956600833";
  public static final String PARTITION = "aws";
  public static final String US_WEST_2 = "us-west-2";

  public static final String[] TEST_KEY_IDS = new String[] {US_WEST_2_KEY_ID, EU_CENTRAL_1_KEY_ID};
}
