/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.encryptionsdk.internal;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.model.CipherFrameHeaders;
import java.lang.reflect.Field;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

public class FrameEncryptionHandlerTest {
  private final CryptoAlgorithm cryptoAlgorithm_ = TestUtils.DEFAULT_TEST_CRYPTO_ALG;
  private final byte[] messageId_ =
      RandomBytesGenerator.generate(cryptoAlgorithm_.getMessageIdLength());
  private final byte nonceLen_ = cryptoAlgorithm_.getNonceLen();
  private final byte[] dataKeyBytes_ =
      RandomBytesGenerator.generate(cryptoAlgorithm_.getKeyLength());
  private final SecretKey encryptionKey_ = new SecretKeySpec(dataKeyBytes_, "AES");
  private final int frameSize_ = AwsCrypto.getDefaultFrameSize();

  private FrameEncryptionHandler frameEncryptionHandler_;

  @Before
  public void setUp() throws Exception {
    frameEncryptionHandler_ =
        new FrameEncryptionHandler(
            encryptionKey_, nonceLen_, cryptoAlgorithm_, messageId_, frameSize_);
  }

  @Test
  public void emptyOutBytes() {
    final int outLen = 0;
    final byte[] out = new byte[outLen];
    final int processedLen = frameEncryptionHandler_.doFinal(out, 0);
    assertEquals(outLen, processedLen);
  }

  @Test
  public void correctIVsGenerated() throws Exception {
    byte[] buf = new byte[frameSize_ + 1024];
    for (int i = 0; i <= 254; i++) {
      byte[] expectedNonce = {
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, (byte) (i + 1)
      };

      generateTestBlock(buf);
      assertHeaderNonce(expectedNonce, buf);
    }

    generateTestBlock(buf);
    assertHeaderNonce(
        new byte[] {
          0, 0, 0, 0,
          0, 0, 0, 0,
          0, 0, 1, 0
        },
        buf);
  }

  @Test
  public void encryptionHandlerEnforcesFrameLimits() throws Exception {
    // Skip to the second-to-last frame first. Actually getting there by encrypting block would take
    // a very long
    // time, so we'll reflect in; for a test that legitimately gets there, see the
    // FrameEncryptionHandlerVeryLongTest.

    Field f = FrameEncryptionHandler.class.getDeclaredField("frameNumber_");
    f.setAccessible(true);
    f.set(frameEncryptionHandler_, 0xFFFF_FFFEL);

    byte[] buf = new byte[frameSize_ + 1024];
    // Writing frame 0xFFFF_FFFE should succeed.
    generateTestBlock(buf);
    assertHeaderNonce(Hex.decode("0000000000000000FFFFFFFE"), buf);

    byte[] oldBuf = buf.clone();
    // Writing the next frame must fail
    assertThrows(() -> generateTestBlock(buf));
    // ... and must not produce any output
    assertArrayEquals(oldBuf, buf);

    // However we can still finish the encryption
    frameEncryptionHandler_.doFinal(buf, 0);
    assertHeaderNonce(Hex.decode("0000000000000000FFFFFFFF"), buf);
  }

  private void assertHeaderNonce(byte[] expectedNonce, byte[] buf) {
    CipherFrameHeaders headers = new CipherFrameHeaders();
    headers.setNonceLength(cryptoAlgorithm_.getNonceLen());
    headers.deserialize(buf, 0);

    assertArrayEquals(expectedNonce, headers.getNonce());
  }

  private void generateTestBlock(byte[] buf) {
    frameEncryptionHandler_.processBytes(new byte[frameSize_], 0, frameSize_, buf, 0);
  }
}
