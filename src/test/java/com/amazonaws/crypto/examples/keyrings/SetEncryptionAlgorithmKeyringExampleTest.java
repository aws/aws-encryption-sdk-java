// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class SetEncryptionAlgorithmKeyringExampleTest {

  @Test
  public void testEncryptAndDecrypt() {
    SetEncryptionAlgorithmKeyringExample.encryptAndDecryptWithKeyring(
        KMSTestFixtures.TEST_KEY_IDS[0]);
  }
}
