package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class CustomizeSDKClientTest {
  @Test
  public void testEncryptAndDecrypt() {
    BasicEncryptionKeyringExample.encryptAndDecryptWithKeyring(KMSTestFixtures.TEST_KEY_IDS[0]);
  }
}
