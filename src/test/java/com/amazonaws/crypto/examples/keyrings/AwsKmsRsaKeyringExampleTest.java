// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class AwsKmsRsaKeyringExampleTest {

  @Test
  public void testEncryptAndDecrypt() {
    AwsKmsRsaKeyringExample.encryptAndDecryptWithKeyring(KMSTestFixtures.US_WEST_2_KMS_RSA_KEY_ID);
  }
}
