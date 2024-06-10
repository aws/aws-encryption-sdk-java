// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.TrailingSignatureAlgorithm;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.model.*;
import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

import static com.amazonaws.encryptionsdk.internal.Utils.assertNonNull;

public class CustomCMMExampleTest {

  @Test
  public void testCustomCMMExample() {
    CryptoMaterialsManager cmm = new CustomCMMExample.SigningSuiteOnlyCMM(
            KmsMasterKeyProvider.builder().buildStrict(KMSTestFixtures.US_WEST_2_KEY_ID)
    );
    CustomCMMExample.encryptAndDecryptWithCMM(cmm);
  }

  @Test
  public void testV2Cmm() {
    V2DefaultCryptoMaterialsManager cmm = new V2DefaultCryptoMaterialsManager(
            KmsMasterKeyProvider.builder().buildStrict(KMSTestFixtures.US_WEST_2_KEY_ID)
    );
    CustomCMMExample.encryptAndDecryptWithCMM(cmm);
  }
}


