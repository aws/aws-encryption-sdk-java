// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class SetCommitmentPolicyKeyringExampleTest {

  @Test
  public void testEncryptAndDecryptKeyrings() {
    SetCommitmentPolicyKeyringExample.encryptAndDecryptWithKeyrings(
        KMSTestFixtures.TEST_KEY_IDS[0]);
  }
}
