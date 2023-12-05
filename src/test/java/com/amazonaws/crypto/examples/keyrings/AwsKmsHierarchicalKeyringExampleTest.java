// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.crypto.examples.keyrings.hierarchical.AwsKmsHierarchicalKeyringExample;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class AwsKmsHierarchicalKeyringExampleTest {
  @Test
  public void testEncryptAndDecrypt() {
    AwsKmsHierarchicalKeyringExample.encryptAndDecryptWithKeyring(
        KMSTestFixtures.TEST_KEYSTORE_NAME,
        KMSTestFixtures.TEST_LOGICAL_KEYSTORE_NAME,
        KMSTestFixtures.TEST_KEYSTORE_KMS_KEY_ID);
  }

  @Test
  public void testEncryptAndDecryptWithKeyringThreadSafe() {
    AwsKmsHierarchicalKeyringExample.encryptAndDecryptWithKeyringThreadSafe(
        KMSTestFixtures.TEST_KEYSTORE_NAME,
        KMSTestFixtures.TEST_LOGICAL_KEYSTORE_NAME,
        KMSTestFixtures.TEST_KEYSTORE_KMS_KEY_ID);
  }
}
