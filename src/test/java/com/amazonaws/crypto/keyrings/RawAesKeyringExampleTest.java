package com.amazonaws.crypto.keyrings;

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
