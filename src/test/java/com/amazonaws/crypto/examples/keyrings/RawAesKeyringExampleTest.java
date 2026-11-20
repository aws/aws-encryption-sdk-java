// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import java.nio.ByteBuffer;
import org.junit.Test;

public class RawAesKeyringExampleTest {
  @Test
  public void testRawAesKeyringExample() {
    // Generate a new AES key
    ByteBuffer aesKeyBytes = RawAesKeyringExample.generateAesKeyBytes();

    RawAesKeyringExample.encryptAndDecryptWithKeyring(aesKeyBytes);
  }
}
