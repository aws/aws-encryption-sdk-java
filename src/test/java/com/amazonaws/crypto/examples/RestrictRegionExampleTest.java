// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class RestrictRegionExampleTest {

  @Test
  public void testEncryptAndDecrypt() {
    RestrictRegionExample.encryptAndDecrypt(
        KMSTestFixtures.US_WEST_2_KEY_ID,
        KMSTestFixtures.PARTITION,
        KMSTestFixtures.ACCOUNT_ID,
        KMSTestFixtures.US_WEST_2);
  }
}
