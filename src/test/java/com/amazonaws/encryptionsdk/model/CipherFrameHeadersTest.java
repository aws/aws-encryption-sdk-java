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

import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.RandomBytesGenerator;
import com.amazonaws.encryptionsdk.internal.TestIOUtils;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.Test;

public class CipherFrameHeadersTest {
  final int nonceLen_ = TestUtils.DEFAULT_TEST_CRYPTO_ALG.getNonceLen();
  final int testSeqNum_ = 1;
  final int testFrameContentLen_ = 4096;
  byte[] nonce_ = RandomBytesGenerator.generate(nonceLen_);

  @Test
  public void serializeDeserializeTest() {
    for (boolean includeContentLen : new boolean[] {true, false}) {
      for (boolean isFinalFrame : new boolean[] {true, false}) {
        assertTrue(serializeDeserialize(includeContentLen, isFinalFrame));
      }
    }
  }

  @Test
  public void serializeDeserializeStreamingTest() {
    for (boolean includeContentLen : new boolean[] {true, false}) {
      for (boolean isFinalFrame : new boolean[] {true, false}) {
        assertTrue(serializeDeserializeStreaming(includeContentLen, isFinalFrame));
      }
    }
  }

  private byte[] createHeaderBytes(final boolean includeContentLen, final boolean isFinalFrame) {
    final CipherFrameHeaders cipherFrameHeaders =
        new CipherFrameHeaders(testSeqNum_, nonce_, testFrameContentLen_, isFinalFrame);
    cipherFrameHeaders.includeFrameSize(includeContentLen);

    return cipherFrameHeaders.toByteArray();
  }

  private CipherFrameHeaders deserialize(final boolean parseContentLen, final byte[] headerBytes) {
    final CipherFrameHeaders reconstructedHeaders = new CipherFrameHeaders();
    reconstructedHeaders.setNonceLength((short) nonceLen_);
    reconstructedHeaders.includeFrameSize(parseContentLen);
    reconstructedHeaders.deserialize(headerBytes, 0);

    return reconstructedHeaders;
  }

  private boolean serializeDeserialize(
      final boolean includeContentLen, final boolean isFinalFrame) {
    final byte[] headerBytes = createHeaderBytes(includeContentLen, isFinalFrame);
    final CipherFrameHeaders reconstructedHeaders = deserialize(includeContentLen, headerBytes);

    final byte[] reconstructedHeaderBytes = reconstructedHeaders.toByteArray();

    return Arrays.equals(headerBytes, reconstructedHeaderBytes) ? true : false;
  }

  private boolean serializeDeserializeStreaming(
      final boolean includeContentLen, final boolean isFinalFrame) {
    final byte[] headerBytes = createHeaderBytes(includeContentLen, isFinalFrame);

    final CipherFrameHeaders reconstructedHeaders = new CipherFrameHeaders();
    reconstructedHeaders.setNonceLength((short) nonceLen_);
    reconstructedHeaders.includeFrameSize(includeContentLen);

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
  public void deserializeNull() {
    final CipherFrameHeaders cipherFrameHeaders = new CipherFrameHeaders();
    final int deserializedBytes = cipherFrameHeaders.deserialize(null, 0);

    assertEquals(0, deserializedBytes);
  }

  @Test
  public void checkNullNonce() {
    final CipherFrameHeaders cipherFrameHeaders = new CipherFrameHeaders();
    cipherFrameHeaders.setNonceLength((short) nonceLen_);

    assertEquals(null, cipherFrameHeaders.getNonce());
  }

  @Test
  public void checkNonce() {
    final byte[] headerBytes = createHeaderBytes(false, false);

    final CipherFrameHeaders reconstructedHeaders = deserialize(false, headerBytes);

    assertArrayEquals(nonce_, reconstructedHeaders.getNonce());
  }

  @Test
  public void checkSeqNum() {
    final byte[] headerBytes = createHeaderBytes(false, false);

    final CipherFrameHeaders reconstructedHeaders = deserialize(false, headerBytes);

    assertEquals(testSeqNum_, reconstructedHeaders.getSequenceNumber());
  }

  @Test
  public void checkFrameLen() {
    final boolean isFinalFrame = false;
    final boolean includeContentLen = true;

    final byte[] headerBytes = createHeaderBytes(includeContentLen, isFinalFrame);

    final CipherFrameHeaders reconstructedHeaders = deserialize(includeContentLen, headerBytes);

    assertEquals(testFrameContentLen_, reconstructedHeaders.getFrameContentLength());
  }

  @Test(expected = BadCiphertextException.class)
  public void invalidFrameLen() {
    final boolean isFinalFrame = false;
    final boolean includeContentLen = true;

    final byte[] headerBytes = createHeaderBytes(includeContentLen, isFinalFrame);
    final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

    // Pull out seq num to move to nonce
    headerBuff.getInt();

    // Pull out nonce to move to content len
    final byte[] nonce = new byte[nonceLen_];
    headerBuff.get(nonce);

    // Set content length (of type long) to -1;
    headerBuff.putInt(-1);

    final CipherFrameHeaders reconstructedHeaders = new CipherFrameHeaders();
    reconstructedHeaders.setNonceLength((short) nonceLen_);
    reconstructedHeaders.includeFrameSize(includeContentLen);
    reconstructedHeaders.deserialize(headerBuff.array(), 0);
  }

  @Test(expected = AwsCryptoException.class)
  public void nullNonce() {
    boolean isFinalFrame = false;
    new CipherFrameHeaders(testSeqNum_, null, testFrameContentLen_, isFinalFrame);
  }

  @Test(expected = AwsCryptoException.class)
  public void invalidNonce() {
    boolean isFinalFrame = false;
    new CipherFrameHeaders(
        testSeqNum_, new byte[Constants.MAX_NONCE_LENGTH + 1], testFrameContentLen_, isFinalFrame);
  }

  @Test
  public void byteFormatCheck() {
    boolean isFinalFrame = false;
    nonce_ = ByteFormatCheckValues.getNonce();
    final CipherFrameHeaders cipherFrameHeaders =
        new CipherFrameHeaders(testSeqNum_, nonce_, testFrameContentLen_, isFinalFrame);

    final byte[] cipherFrameHeaderHash =
        TestIOUtils.getSha256Hash(cipherFrameHeaders.toByteArray());

    assertArrayEquals(ByteFormatCheckValues.getCipherFrameHeaderHash(), cipherFrameHeaderHash);
  }

  @Test
  public void byteFormatCheckforFinalFrame() {
    boolean isFinalFrame = true;
    nonce_ = ByteFormatCheckValues.getNonce();
    final CipherFrameHeaders cipherFinalFrameHeaders =
        new CipherFrameHeaders(testSeqNum_, nonce_, testFrameContentLen_, isFinalFrame);

    final byte[] cipherFinalFrameHeaderHash =
        TestIOUtils.getSha256Hash(cipherFinalFrameHeaders.toByteArray());

    assertArrayEquals(
        ByteFormatCheckValues.getCipherFinalFrameHeaderHash(), cipherFinalFrameHeaderHash);
  }
}
