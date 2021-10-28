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

public class BlockDecryptionHandlerTest {
  private static final SecureRandom RND = new SecureRandom();
  private final CryptoAlgorithm cryptoAlgorithm_ = TestUtils.DEFAULT_TEST_CRYPTO_ALG;
  private final byte[] messageId_ = new byte[cryptoAlgorithm_.getMessageIdLength()];
  private final byte nonceLen_ = cryptoAlgorithm_.getNonceLen();
  private final byte[] dataKeyBytes_ = new byte[cryptoAlgorithm_.getKeyLength()];
  private final SecretKey dataKey_ = new SecretKeySpec(dataKeyBytes_, "AES");

  private final BlockDecryptionHandler blockDecryptionHandler_ =
      new BlockDecryptionHandler(dataKey_, nonceLen_, cryptoAlgorithm_, messageId_);

  @Before
  public void setup() {
    RND.nextBytes(messageId_);
    RND.nextBytes(dataKeyBytes_);
  }

  @Test
  public void estimateOutputSize() {
    final int inLen = 1;
    final int outSize = blockDecryptionHandler_.estimateOutputSize(inLen);

    // the estimated output size must at least be equal to inLen.
    assertTrue(outSize >= inLen);
  }

  @Test(expected = BadCiphertextException.class)
  public void doFinalCalledWhileNotComplete() {
    blockDecryptionHandler_.doFinal(new byte[1], 0);
  }

  @Test(expected = AwsCryptoException.class)
  public void decryptMaxContentLength() {
    final BlockEncryptionHandler blockEncryptionHandler =
        new BlockEncryptionHandler(dataKey_, nonceLen_, cryptoAlgorithm_, messageId_);
    final byte[] in = new byte[0];
    final int outLen = blockEncryptionHandler.estimateOutputSize(in.length);
    final byte[] out = new byte[outLen];

    blockEncryptionHandler.processBytes(in, 0, in.length, out, 0);
    blockEncryptionHandler.doFinal(out, 0);

    final ByteBuffer outBuff = ByteBuffer.wrap(out);
    // pull out nonce to get to content length.
    final byte[] nonce = new byte[nonceLen_];
    outBuff.get(nonce);
    // set content length to integer max value + 1.
    outBuff.putLong(Integer.MAX_VALUE + 1L);

    final int decryptedOutLen = blockDecryptionHandler_.estimateOutputSize(outLen);
    final byte[] decryptedOut = new byte[decryptedOutLen];
    blockDecryptionHandler_.processBytes(
        outBuff.array(), 0, outBuff.array().length, decryptedOut, 0);
  }

  @Test(expected = AwsCryptoException.class)
  public void processBytesCalledWhileComplete() {
    final BlockEncryptionHandler blockEncryptionHandler =
        new BlockEncryptionHandler(dataKey_, nonceLen_, cryptoAlgorithm_, messageId_);
    final byte[] in = new byte[0];
    final int outLen = blockEncryptionHandler.estimateOutputSize(in.length);
    final byte[] out = new byte[outLen];

    blockEncryptionHandler.processBytes(in, 0, in.length, out, 0);
    blockEncryptionHandler.doFinal(out, 0);

    final byte[] decryptedOut = new byte[outLen];
    blockDecryptionHandler_.processBytes(out, 0, outLen, decryptedOut, 0);
    blockDecryptionHandler_.processBytes(out, 0, outLen, decryptedOut, 0);
  }
}
