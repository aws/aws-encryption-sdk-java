// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class BasicMultiRegionKeyEncryptionExampleTest {

  @Test
  public void testEncryptAndDecrypt() {
    BasicMultiRegionKeyEncryptionExample.encryptAndDecrypt(
        KMSTestFixtures.US_EAST_1_MULTI_REGION_KEY_ID,
        KMSTestFixtures.US_WEST_2_MULTI_REGION_KEY_ID);
  }
}
