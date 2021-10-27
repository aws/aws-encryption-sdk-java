// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.ParsedCiphertext;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

import static org.junit.Assert.*;

public class SimpleDataKeyCachingExampleTest {
  private static final int MAX_ENTRY_AGE = 100;
  private static final int CACHE_CAPACITY = 1000;

  @Test
  public void testEncryptWithCaching() {
    final byte[] result =
        SimpleDataKeyCachingExample.encryptWithCaching(
            KMSTestFixtures.TEST_KEY_IDS[0], MAX_ENTRY_AGE, CACHE_CAPACITY);
    assertNotNull(result);
    final ParsedCiphertext parsedResult = new ParsedCiphertext(result);
    assertEquals(1, parsedResult.getEncryptedKeyBlobs().size());
    assertArrayEquals(
        KMSTestFixtures.TEST_KEY_IDS[0].getBytes(),
        parsedResult.getEncryptedKeyBlobs().get(0).getProviderInformation());
  }
}
