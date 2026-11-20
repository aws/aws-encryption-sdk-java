// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import org.junit.Test;

public class CustomCMMExampleTest {

  @Test
  public void testCustomCMMExample() {
    CryptoMaterialsManager cmm =
        new CustomCMMExample.SigningSuiteOnlyCMM(
            KmsMasterKeyProvider.builder().buildStrict(KMSTestFixtures.US_WEST_2_KEY_ID));
    CustomCMMExample.encryptAndDecryptWithCMM(cmm);
  }

  @Test
  public void testV2Cmm() {
    V2DefaultCryptoMaterialsManager cmm =
        new V2DefaultCryptoMaterialsManager(
            KmsMasterKeyProvider.builder().buildStrict(KMSTestFixtures.US_WEST_2_KEY_ID));
    CustomCMMExample.encryptAndDecryptWithCMM(cmm);
  }
}
