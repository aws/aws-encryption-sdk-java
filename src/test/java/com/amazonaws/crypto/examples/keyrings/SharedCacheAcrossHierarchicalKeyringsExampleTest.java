// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.crypto.examples.keyrings.hierarchical.SharedCacheAcrossHierarchicalKeyringsExample;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class SharedCacheAcrossHierarchicalKeyringsExampleTest {
  @Test
  public void testEncryptAndDecrypt() {
    SharedCacheAcrossHierarchicalKeyringsExample.encryptAndDecryptWithKeyring(
        KMSTestFixtures.TEST_KEYSTORE_NAME,
        KMSTestFixtures.TEST_LOGICAL_KEYSTORE_NAME,
        KMSTestFixtures.HIERARCHY_KEYRING_PARTITION_ID,
        KMSTestFixtures.TEST_KEYSTORE_KMS_KEY_ID);
  }
}
