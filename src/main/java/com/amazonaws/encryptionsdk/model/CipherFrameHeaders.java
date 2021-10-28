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

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.exception.ParseException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.PrimitivesParser;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * This class implements the headers for the encrypted content stored in a frame. These headers are
 * parsed and used when the encrypted content in the frame is decrypted.
 *
 * <p>It contains the following fields in order:
 *
 * <ol>
 *   <li>final sequence number marker if final frame
 *   <li>sequence number
 *   <li>nonce
 *   <li>length of content in frame
 * </ol>
 */
public final class CipherFrameHeaders {
  private int sequenceNumber_ = 0; // this is okay since sequence numbers in
  // frames start at 1
  private byte[] nonce_;
  private int frameContentLength_ = -1;

  // This is set after the nonce length is parsed in the CiphertextHeaders
  // during decryption. This can be set only using its setter.
  private short nonceLength_ = 0;

  private boolean includeFrameSize_;
  private boolean isComplete_;
  private boolean isFinalFrame_;

  /** Default constructor. */
  public CipherFrameHeaders() {}

  /**
   * Construct the frame headers using the provided sequence number, nonce, length of content, and
   * boolean value indicating if it is the final frame.
   *
   * @param sequenceNumber the sequence number of the frame
   * @param nonce the bytes containing the nonce.
   * @param frameContentLen the length of the content in the frame.
   * @param isFinal boolean value indicating if it is the final frame.
   */
  public CipherFrameHeaders(
      final int sequenceNumber,
      final byte[] nonce,
      final int frameContentLen,
      final boolean isFinal) {
    sequenceNumber_ = sequenceNumber;

    if (nonce == null) {
      throw new AwsCryptoException("Nonce cannot be null.");
    }
    if (nonce.length > Constants.MAX_NONCE_LENGTH) {
      throw new AwsCryptoException(
          "Nonce length is greater than the maximum value of an unsigned byte.");
    }

    nonce_ = nonce.clone();
    isFinalFrame_ = isFinal;
    frameContentLength_ = frameContentLen;
  }

  /**
   * Serialize the header into a byte array.
   *
   * @return the serialized bytes of the header.
   */
  public byte[] toByteArray() {
    try {
      ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
      DataOutputStream dataStream = new DataOutputStream(outBytes);

      if (isFinalFrame_) {
        dataStream.writeInt(Constants.ENDFRAME_SEQUENCE_NUMBER);
      }

      dataStream.writeInt(sequenceNumber_);
      dataStream.write(nonce_);

      if (includeFrameSize_ || isFinalFrame_) {
        dataStream.writeInt(frameContentLength_);
      }

      dataStream.close();
      return outBytes.toByteArray();
    } catch (IOException e) {
      throw new AwsCryptoException("Failed to serialize cipher frame headers", e);
    }
  }

  /**
   * Parse the sequence number in the provided bytes. It looks for 4 bytes representing a integer
   * primitive type in the provided bytes starting at the specified offset.
   *
   * <p>If successful, it returns the size of the parsed bytes which is the size of the integer
   * primitive type. On failure, it throws a parse exception.
   *
   * @param b the byte array to parse.
   * @param off the offset in the byte array to use when parsing.
   * @return the size of the parsed bytes which is the size of the integer primitive type.
   * @throws ParseException if there are not sufficient bytes to parse the sequence number.
   */
  private int parseSequenceNumber(final byte[] b, final int off) throws ParseException {
    sequenceNumber_ = PrimitivesParser.parseInt(b, off);
    return Integer.SIZE / Byte.SIZE;
  }

  /**
   * Parse the nonce in the provided bytes. It looks for bytes of size defined by the nonce length
   * in the provided bytes starting at the specified off.
   *
   * <p>If successful, it returns the size of the parsed bytes which is the nonce length. On
   * failure, it throws a parse exception.
   *
   * @param b the byte array to parse.
   * @param off the offset in the byte array to use when parsing.
   * @return the size of the parsed bytes which is the nonce length.
   * @throws ParseException if there are not sufficient bytes to parse the nonce.
   */
  private int parseNonce(final byte[] b, final int off) throws ParseException {
    final int bytesToParseLen = b.length - off;
    if (bytesToParseLen >= nonceLength_) {
      nonce_ = Arrays.copyOfRange(b, off, off + nonceLength_);
      return nonceLength_;
    } else {
      throw new ParseException("Not enough bytes to parse nonce");
    }
  }

  /**
   * Parse the frame content length in the provided bytes. It looks for 4 bytes representing an
   * integer primitive type in the provided bytes starting at the specified off.
   *
   * <p>If successful, it returns the size of the parsed bytes which is the size of the integer
   * primitive type. On failure, it throws a parse exception.
   *
   * @param b the byte array to parse.
   * @param off the offset in the byte array to use when parsing.
   * @return the size of the parsed bytes which is the size of the integer primitive type.
   * @throws ParseException if there are not sufficient bytes to parse the frame content length.
   */
  private int parseFrameContentLength(final byte[] b, final int off) throws ParseException {
    frameContentLength_ = PrimitivesParser.parseInt(b, off);
    if (frameContentLength_ < 0) {
      throw new BadCiphertextException("Invalid frame length in ciphertext");
    }
    return Integer.SIZE / Byte.SIZE;
  }

  /**
   * Deserialize the provided bytes starting at the specified offset to construct an instance of
   * this class.
   *
   * <p>This method parses the provided bytes for the individual fields in this class. This methods
   * also supports partial parsing where not all the bytes required for parsing the fields
   * successfully are available.
   *
   * @param b the byte array to deserialize.
   * @param off the offset in the byte array to use for deserialization.
   * @return the number of bytes consumed in deserialization.
   */
  public int deserialize(final byte[] b, final int off) {
    if (b == null) {
      return 0;
    }

    int parsedBytes = 0;
    try {
      if (sequenceNumber_ == 0) {
        parsedBytes += parseSequenceNumber(b, off + parsedBytes);
      }

      // parse the sequence number again if the sequence number parsed in
      // the previous call is the final frame marker and this frame hasn't
      // already been marked final.
      if (sequenceNumber_ == Constants.ENDFRAME_SEQUENCE_NUMBER && !isFinalFrame_) {
        parsedBytes += parseSequenceNumber(b, off + parsedBytes);
        isFinalFrame_ = true;
      }

      if (nonceLength_ > 0 && nonce_ == null) {
        parsedBytes += parseNonce(b, off + parsedBytes);
      }

      if (includeFrameSize_ || isFinalFrame_) {
        if (frameContentLength_ < 0) {
          parsedBytes += parseFrameContentLength(b, off + parsedBytes);
        }
      }

      isComplete_ = true;
    } catch (ParseException e) {
      // this results when we do partial parsing and there aren't enough
      // bytes to parse; so just return the bytes parsed thus far.
    }

    return parsedBytes;
  }

  /**
   * Return if the frame is a final frame. The final frame is identified as the frame containing the
   * final sequence number marker.
   *
   * @return true if final frame; false otherwise.
   */
  public boolean isFinalFrame() {
    return isFinalFrame_;
  }

  /**
   * Check if this object has all the header fields populated and available for reading.
   *
   * @return true if this object containing the single block header fields is complete; false
   *     otherwise.
   */
  public boolean isComplete() {
    return isComplete_;
  }

  /**
   * Return the nonce set in the frame header.
   *
   * @return the bytes containing the nonce set in the frame header.
   */
  public byte[] getNonce() {
    return nonce_ != null ? nonce_.clone() : null;
  }

  /**
   * Return the frame content length set in the frame header.
   *
   * @return the frame content length set in the frame header.
   */
  public int getFrameContentLength() {
    return frameContentLength_;
  }

  /**
   * Return the frame sequence number set in the frame header.
   *
   * @return the frame sequence number set in the frame header.
   */
  public int getSequenceNumber() {
    return sequenceNumber_;
  }

  /**
   * Set the length of the nonce used in the encryption of the content in the frame.
   *
   * @param nonceLength the length of the nonce used in the encryption of the content in the frame.
   */
  public void setNonceLength(final short nonceLength) {
    nonceLength_ = nonceLength;
  }

  /**
   * Set the flag to specify whether the frame length needs to be included or parsed in the header.
   *
   * @param value true if the frame length needs to be included or parsed in the header; false
   *     otherwise
   */
  public void includeFrameSize(final boolean value) {
    includeFrameSize_ = true;
  }
}
