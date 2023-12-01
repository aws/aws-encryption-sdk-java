// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class SetEncryptionAlgorithmExampleTest {

  @Test
  public void testEncryptAndDecrypt() {
    SetEncryptionAlgorithmExample.encryptAndDecrypt(KMSTestFixtures.TEST_KEY_IDS[0]);
  }
}
