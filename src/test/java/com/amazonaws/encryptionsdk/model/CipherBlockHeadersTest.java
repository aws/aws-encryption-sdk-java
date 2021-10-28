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

package com.amazonaws.encryptionsdk.model;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.RandomBytesGenerator;
import com.amazonaws.encryptionsdk.internal.TestIOUtils;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.Test;

public class CipherBlockHeadersTest {
  final int nonceLen_ = 12;
  byte[] nonce_ = RandomBytesGenerator.generate(nonceLen_);
  final int sampleContentLen_ = 1024;

  @Test
  public void serializeDeserialize() {
    final CipherBlockHeaders cipherBlockHeaders = new CipherBlockHeaders(nonce_, sampleContentLen_);

    final byte[] headerBytes = cipherBlockHeaders.toByteArray();

    final CipherBlockHeaders reconstructedHeaders = new CipherBlockHeaders();
    reconstructedHeaders.setNonceLength((short) nonceLen_);
    reconstructedHeaders.deserialize(headerBytes, 0);
    final byte[] reconstructedHeaderBytes = reconstructedHeaders.toByteArray();

    assertArrayEquals(headerBytes, reconstructedHeaderBytes);
  }

  private boolean serializeDeserializeStreaming(final boolean isFinalFrame) {
    final CipherBlockHeaders cipherBlockHeaders = new CipherBlockHeaders(nonce_, sampleContentLen_);

    final byte[] headerBytes = cipherBlockHeaders.toByteArray();
    final CipherBlockHeaders reconstructedHeaders = new CipherBlockHeaders();
    reconstructedHeaders.setNonceLength((short) nonceLen_);

    int totalParsedBytes = 0;
    int bytesToParseLen = 1;
    int bytesParsed;

    while (reconstructedHeaders.isComplete() == false) {
      final byte[] bytesToParse = new byte[bytesToParseLen];
      System.arraycopy(headerBytes, totalParsedBytes, bytesToParse, 0, bytesToParse.length);

      bytesParsed = reconstructedHeaders.deserialize(bytesToParse, 0);
      if (bytesParsed == 0) {
        bytesToParseLen++;
      } else {
        totalParsedBytes += bytesParsed;
        bytesToParseLen = 1;
      }
    }

    final byte[] reconstructedHeaderBytes = reconstructedHeaders.toByteArray();

    return Arrays.equals(headerBytes, reconstructedHeaderBytes) ? true : false;
  }

  @Test
  public void serializeDeserializeStreamingFinalFrame() {
    assertTrue(serializeDeserializeStreaming(true));
  }

  @Test
  public void deserializeNull() {
    final CipherBlockHeaders cipherBlockHeaders = new CipherBlockHeaders();
    final int deserializedBytes = cipherBlockHeaders.deserialize(null, 0);

    assertEquals(0, deserializedBytes);
  }

  @Test
  public void checkContentLen() {
    final CipherBlockHeaders cipherBlockHeaders = new CipherBlockHeaders(nonce_, sampleContentLen_);
    final byte[] headerBytes = cipherBlockHeaders.toByteArray();

    final CipherBlockHeaders reconstructedHeaders = new CipherBlockHeaders();
    reconstructedHeaders.setNonceLength((short) nonceLen_);
    reconstructedHeaders.deserialize(headerBytes, 0);

    assertEquals(sampleContentLen_, reconstructedHeaders.getContentLength());
  }

  @Test
  public void checkNonce() {
    final CipherBlockHeaders cipherBlockHeaders = new CipherBlockHeaders(nonce_, sampleContentLen_);
    final byte[] headerBytes = cipherBlockHeaders.toByteArray();

    final CipherBlockHeaders reconstructedHeaders = new CipherBlockHeaders();
    reconstructedHeaders.setNonceLength((short) nonceLen_);
    reconstructedHeaders.deserialize(headerBytes, 0);

    assertArrayEquals(nonce_, reconstructedHeaders.getNonce());
  }

  @Test
  public void checkNullNonce() {
    final CipherBlockHeaders cipherBlockHeaders = new CipherBlockHeaders();
    cipherBlockHeaders.setNonceLength((short) nonceLen_);

    assertArrayEquals(null, cipherBlockHeaders.getNonce());
  }

  @Test(expected = AwsCryptoException.class)
  public void nullNonce() {
    new CipherBlockHeaders(null, sampleContentLen_);
  }

  @Test(expected = AwsCryptoException.class)
  public void invalidNonce() {
    new CipherBlockHeaders(new byte[Constants.MAX_NONCE_LENGTH + 1], sampleContentLen_);
  }

  @Test(expected = BadCiphertextException.class)
  public void invalidContentLen() {
    final CipherBlockHeaders cipherBlockHeaders = new CipherBlockHeaders(nonce_, sampleContentLen_);
    final byte[] headerBytes = cipherBlockHeaders.toByteArray();
    final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

    // Pull out nonce to move to content len
    final byte[] nonce = new byte[nonceLen_];
    headerBuff.get(nonce);

    // Set content length (of type long) to -1;
    headerBuff.putLong(-1);

    final CipherBlockHeaders reconstructedHeaders = new CipherBlockHeaders();
    reconstructedHeaders.setNonceLength((short) nonceLen_);
    reconstructedHeaders.deserialize(headerBuff.array(), 0);
  }

  @Test
  public void byteFormatCheck() {
    nonce_ = ByteFormatCheckValues.getNonce();
    final CipherBlockHeaders cipherBlockHeaders = new CipherBlockHeaders(nonce_, sampleContentLen_);

    final byte[] cipherBlockHeaderHash =
        TestIOUtils.getSha256Hash(cipherBlockHeaders.toByteArray());

    assertArrayEquals(ByteFormatCheckValues.getCipherBlockHeaderHash(), cipherBlockHeaderHash);
  }
}
