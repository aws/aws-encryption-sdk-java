// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class BasicEncryptionExampleTest {

  @Test
  public void testEncryptAndDecrypt() {
    BasicEncryptionExample.encryptAndDecrypt(KMSTestFixtures.TEST_KEY_IDS[0]);
  }
}
