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

import static org.junit.Assert.assertTrue;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Before;
import org.junit.Test;

public class FrameDecryptionHandlerTest {
  private static final SecureRandom RND = new SecureRandom();
  private final CryptoAlgorithm cryptoAlgorithm_ = TestUtils.DEFAULT_TEST_CRYPTO_ALG;
  private final byte[] messageId_ = new byte[cryptoAlgorithm_.getMessageIdLength()];
  private final byte nonceLen_ = cryptoAlgorithm_.getNonceLen();
  private final byte[] dataKeyBytes_ = new byte[cryptoAlgorithm_.getKeyLength()];
  private final SecretKey dataKey_ = new SecretKeySpec(dataKeyBytes_, "AES");
  private final int frameSize_ = AwsCrypto.getDefaultFrameSize();

  private final FrameDecryptionHandler frameDecryptionHandler_ =
      new FrameDecryptionHandler(dataKey_, nonceLen_, cryptoAlgorithm_, messageId_, frameSize_);

  @Before
  public void setup() {
    RND.nextBytes(messageId_);
    RND.nextBytes(dataKeyBytes_);
  }

  @Test
  public void estimateOutputSize() {
    final int inLen = 1;
    final int outSize = frameDecryptionHandler_.estimateOutputSize(inLen);

    // the estimated output size must at least be equal to inLen.
    assertTrue(outSize >= inLen);
  }

  @Test(expected = AwsCryptoException.class)
  public void decryptMaxContentLength() {
    // Create input of size 1 byte: 1 byte of the sequence number,
    // Only 1 byte of the sequence number is provided because this
    // forces the frame decryption handler to buffer that 1 byte while
    // waiting for the remaining bytes of the sequence number. We do this so
    // we can specify an input of max value and the total bytes to parse
    // will become max value + 1.
    final byte[] in = new byte[1];
    final byte[] out = new byte[1];

    frameDecryptionHandler_.processBytes(in, 0, in.length, out, 0);
    frameDecryptionHandler_.processBytes(in, 0, Integer.MAX_VALUE, out, 0);
  }

  @Test(expected = BadCiphertextException.class)
  public void finalFrameLengthTooLarge() {

    final ByteBuffer byteBuffer = ByteBuffer.allocate(25);
    byteBuffer.put(
        TestUtils.unsignedBytesToSignedBytes(
            new int[] {255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}));
    byteBuffer.putInt(AwsCrypto.getDefaultFrameSize() + 1);

    final byte[] in = byteBuffer.array();
    final byte[] out = new byte[in.length];

    frameDecryptionHandler_.processBytes(in, 0, in.length, out, 0);
  }

  @Test(expected = BadCiphertextException.class)
  public void doFinalCalledWhileNotComplete() {
    frameDecryptionHandler_.doFinal(new byte[1], 0);
  }

  @Test(expected = AwsCryptoException.class)
  public void processBytesCalledWhileComplete() {
    final FrameEncryptionHandler frameEncryptionHandler =
        new FrameEncryptionHandler(dataKey_, nonceLen_, cryptoAlgorithm_, messageId_, frameSize_);
    final byte[] in = new byte[0];
    final int outLen = frameEncryptionHandler.estimateOutputSize(in.length);
    final byte[] out = new byte[outLen];

    frameEncryptionHandler.processBytes(in, 0, in.length, out, 0);
    frameEncryptionHandler.doFinal(out, 0);

    final byte[] decryptedOut = new byte[outLen];

    frameDecryptionHandler_.processBytes(out, 0, out.length, decryptedOut, 0);
    frameDecryptionHandler_.processBytes(out, 0, out.length, decryptedOut, 0);
  }
}
