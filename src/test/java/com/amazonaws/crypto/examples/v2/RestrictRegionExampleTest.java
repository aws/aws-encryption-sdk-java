// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;
import software.amazon.awssdk.regions.Region;

public class RestrictRegionExampleTest {

  @Test
  public void testEncryptAndDecrypt() {
    RestrictRegionExample.encryptAndDecrypt(
        KMSTestFixtures.US_WEST_2_KEY_ID,
        KMSTestFixtures.PARTITION,
        KMSTestFixtures.ACCOUNT_ID,
        Region.US_WEST_2);
  }
}
