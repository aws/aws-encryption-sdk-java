package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import java.nio.ByteBuffer;
import org.junit.Test;

public class MultiKeyringExampleTest {
  @Test
  public void testEncryptAndDecrypt() {
    // Generate a new AES key
    ByteBuffer aesKeyBytes = MultiKeyringExample.generateAesKeyBytes();

    MultiKeyringExample.encryptAndDecryptWithKeyring(KMSTestFixtures.TEST_KEY_IDS[0], aesKeyBytes);
  }
}
