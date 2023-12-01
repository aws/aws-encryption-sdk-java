// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;
import software.amazon.awssdk.regions.Region;

public class DiscoveryMultiRegionDecryptionExampleTest {

  @Test
  public void testEncryptAndDecrypt() {
    DiscoveryMultiRegionDecryptionExample.encryptAndDecrypt(
        KMSTestFixtures.US_EAST_1_MULTI_REGION_KEY_ID,
        KMSTestFixtures.PARTITION,
        KMSTestFixtures.ACCOUNT_ID,
        Region.US_WEST_2);
  }
}
