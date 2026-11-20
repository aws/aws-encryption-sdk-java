// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import org.junit.Test;

public class RawRsaKeyringExampleTest {
  @Test
  public void testRawAesKeyringExample() {
    KeyPair keyPair = RawRsaKeyringExample.generateKeyPair();
    ByteBuffer publicKeyBytes = RawRsaKeyringExample.getPEMPublicKey(keyPair.getPublic());
    ByteBuffer privateKeyBytes = RawRsaKeyringExample.getPEMPrivateKey(keyPair.getPrivate());

    RawRsaKeyringExample.encryptAndDecryptWithKeyring(publicKeyBytes, privateKeyBytes);
  }
}
