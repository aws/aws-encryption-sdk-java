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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.model.CipherBlockHeaders;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Before;
import org.junit.Test;

public class BlockEncryptionHandlerTest {
  private final CryptoAlgorithm cryptoAlgorithm_ = TestUtils.DEFAULT_TEST_CRYPTO_ALG;
  private final byte[] messageId_ =
      RandomBytesGenerator.generate(cryptoAlgorithm_.getMessageIdLength());
  private final byte nonceLen_ = cryptoAlgorithm_.getNonceLen();
  private final byte[] dataKeyBytes_ =
      RandomBytesGenerator.generate(cryptoAlgorithm_.getKeyLength());
  private final SecretKey encryptionKey_ = new SecretKeySpec(dataKeyBytes_, "AES");

  private BlockEncryptionHandler blockEncryptionHandler_;

  @Before
  public void setUp() throws Exception {
    blockEncryptionHandler_ =
        new BlockEncryptionHandler(encryptionKey_, nonceLen_, cryptoAlgorithm_, messageId_);
  }

  @Test
  public void emptyOutBytes() {
    final int outLen = 0;
    final byte[] out = new byte[outLen];
    final int processedLen = blockEncryptionHandler_.doFinal(out, 0);
    assertEquals(outLen, processedLen);
  }

  @Test
  public void correctIVGenerated() throws Exception {
    final byte[] out = new byte[1024];
    int outOff = blockEncryptionHandler_.processBytes(new byte[1], 0, 1, out, 0).getBytesWritten();
    final int processedLen = blockEncryptionHandler_.doFinal(out, outOff);

    CipherBlockHeaders headers = new CipherBlockHeaders();
    headers.setNonceLength(cryptoAlgorithm_.getNonceLen());
    headers.deserialize(out, 0);

    assertArrayEquals(
        new byte[] {
          0, 0, 0, 0,
          0, 0, 0, 0,
          0, 0, 0, 1
        },
        headers.getNonce());
  }
}
