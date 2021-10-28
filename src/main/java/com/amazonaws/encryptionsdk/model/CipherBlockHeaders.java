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
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * This class implements the headers for the encrypted content stored in a single block. These
 * headers are parsed and used when the encrypted content in the single block is decrypted.
 *
 * <p>It contains the following fields in order:
 *
 * <ol>
 *   <li>nonce
 *   <li>length of content
 * </ol>
 */
// @ non_null_by_default
public final class CipherBlockHeaders {
  // @ spec_public nullable
  private byte[] nonce_;
  // @ spec_public
  private long contentLength_ = -1;

  // This is set after the nonce length is parsed in the CiphertextHeaders
  // during decryption. This can be set only using its setter.
  // @ spec_public
  private short nonceLength_ = 0;
  // @ public invariant nonceLength_ >= 0;

  // @ spec_public
  private boolean isComplete_;

  /** Default constructor. */
  // @ public normal_behavior
  // @   ensures nonce_ == null;
  // @   ensures contentLength_ == -1;
  // @   ensures nonceLength_ == 0;
  // @   ensures isComplete_ == false;
  public CipherBlockHeaders() {}

  /**
   * Construct the single block headers using the provided nonce and length of content.
   *
   * @param nonce the bytes containing the nonce.
   * @param contentLen the length of the content in the block.
   */
  // @ public normal_behavior
  // @   requires nonce != null && nonce.length <= Constants.MAX_NONCE_LENGTH;
  // @   ensures \fresh(nonce_) && nonce_.length == nonce.length;
  // @   ensures Arrays.equalArrays(nonce_, nonce);
  // @   ensures contentLength_ == contentLen;
  // @   ensures nonceLength_ == 0;
  // @   ensures isComplete_ == false;
  // @ also private exceptional_behavior
  // @   requires nonce == null || nonce.length > Constants.MAX_NONCE_LENGTH;
  // @   signals_only AwsCryptoException;
  // @ pure
  public CipherBlockHeaders(/*@ nullable @*/ final byte[] nonce, final long contentLen) {
    if (nonce == null) {
      throw new AwsCryptoException("Nonce cannot be null.");
    }
    if (nonce.length > Constants.MAX_NONCE_LENGTH) {
      throw new AwsCryptoException(
          "Nonce length is greater than the maximum value of an unsigned byte.");
    }

    nonce_ = nonce.clone();
    contentLength_ = contentLen;
  }

  /**
   * Serialize the header into a byte array.
   *
   * @return the serialized bytes of the header.
   */
  /*@ public normal_behavior
  @   requires nonce_ != null;
  @   old int nLen = nonce_.length;
  @   requires nonce_.length <= Integer.MAX_VALUE - (Long.SIZE / Byte.SIZE);
  @   ensures \result.length == nonce_.length + (Long.SIZE / Byte.SIZE);
  @   ensures (\forall int i; 0<=i && i<nonce_.length; \result[i] == nonce_[i]);
  @   ensures contentLength_ == Long.asLong(\result[nLen], \result[nLen+1], \result[nLen+2],
  @                                         \result[nLen+3], \result[nLen+4], \result[nLen+5],
  @                                         \result[nLen+6], \result[nLen+7]);
  @ pure
  @*/
  public byte[] toByteArray() {
    final int outLen = nonce_.length + (Long.SIZE / Byte.SIZE);
    final ByteBuffer out = ByteBuffer.allocate(outLen);

    out.put(nonce_);
    out.putLong(contentLength_);

    return out.array();
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
  // @ private normal_behavior
  // @   requires nonceLength_ > 0;
  // @   requires 0 <= off;
  // @   requires b.length - off >= nonceLength_;
  // @   assignable nonce_;
  // @   ensures nonce_ != null && \fresh(nonce_);
  // @   ensures Arrays.equalArrays(b, off, nonce_, 0, nonceLength_);
  // @   ensures \result == nonceLength_;
  // @ also private exceptional_behavior
  // @   // add exceptions from arrays.copyofrange
  // @   requires b.length - off < nonceLength_;
  // @   assignable \nothing;
  // @   signals_only ParseException;
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
   * Parse the content length in the provided bytes. It looks for 8 bytes representing a long
   * primitive type in the provided bytes starting at the specified off.
   *
   * <p>If successful, it returns the size of the parsed bytes which is the size of the long
   * primitive type. On failure, it throws a parse exception.
   *
   * @param b the byte array to parse.
   * @param off the offset in the byte array to use when parsing.
   * @return the size of the parsed bytes which is the size of the long primitive type.
   * @throws ParseException if there are not sufficient bytes to parse the content length.
   */
  // @ private behavior
  // @   requires off >= 0;
  // @   requires b.length - off >= Long.BYTES;
  // @   old long len =
  // Long.asLong(b[off],b[off+1],b[off+2],b[off+3],b[off+4],b[off+5],b[off+6],b[off+7]);
  // @   assignable contentLength_;
  // @   ensures len >= 0;
  // @   ensures contentLength_ == len;
  // @   ensures \result == Long.BYTES;
  // @   signals_only BadCiphertextException;
  // @   signals (BadCiphertextException) len < 0 && contentLength_ == len;
  // @ also private exceptional_behavior
  // @   requires b.length - off < Long.BYTES;
  // @   assignable \nothing;
  // @   signals_only ParseException;
  private int parseContentLength(final byte[] b, final int off) throws ParseException {
    contentLength_ = PrimitivesParser.parseLong(b, off);
    if (contentLength_ < 0) {
      throw new BadCiphertextException("Invalid content length in ciphertext");
    }
    return Long.SIZE / Byte.SIZE;
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
  /*@ public normal_behavior
  @   requires b == null;
  @   assignable \nothing;
  @   ensures \result == 0;
  @ also
  @ // case: do not need to parse either value
  @ public normal_behavior
  @   requires b != null && contentLength_ >= 0 && (nonce_ != null || nonceLength_ == 0);
  @   assignable isComplete_;
  @   ensures \result == 0;
  @   ensures isComplete_;
  @ also
  @ // case: parse nonce (parse exception)
  @ public normal_behavior
  @   requires b != null && nonce_ == null && nonceLength_ > 0;
  @   requires b.length - off < nonceLength_;
  @   assignable \nothing;
  @   ensures \result == 0;
  @ also
  @ // case: parse nonce (normally) and not content length
  @ public normal_behavior
  @   requires b != null && nonce_ == null && nonceLength_ > 0;
  @   requires off >= 0 && b.length - off >= nonceLength_;
  @   requires contentLength_ >= 0;
  @   assignable nonce_, isComplete_;
  @   ensures nonce_ != null && \fresh(nonce_);
  @   ensures Arrays.equalArrays(b, off, nonce_, 0, nonceLength_);
  @   ensures \result == nonceLength_;
  @   ensures isComplete_;
  @ also
  @ // case: do not parse nonce and parse content length (parse exception)
  @ public normal_behavior
  @   requires b != null && (nonce_ != null || nonceLength_ == 0);
  @   requires contentLength_ < 0;
  @   requires b.length - off < Long.BYTES;
  @   assignable \nothing;
  @   ensures \result == 0;
  @ also
  @ // case: parse nonce (normally) and parse content length (parse exception)
  @ public normal_behavior
  @   requires b != null && nonce_ == null && nonceLength_ > 0;
  @   requires off >= 0 && b.length - off >= nonceLength_;
  @   requires contentLength_ < 0;
  @   requires b.length - (off + nonceLength_) < Long.BYTES;
  @   assignable nonce_;
  @   ensures Arrays.equalArrays(b, off, nonce_, 0, nonceLength_);
  @   ensures \result == nonceLength_;
  @ also
  @ // case: do not parse nonce and parse content length (normally)
  @ public behavior
  @   requires b != null && (nonce_ != null || nonceLength_ == 0);
  @   requires contentLength_ < 0;
  @   requires off >= 0;
  @   requires b.length - off >= Long.BYTES;
  @   assignable contentLength_, isComplete_;
  @   ensures isComplete_ && contentLength_ >= 0;
  @   ensures contentLength_ == Long.asLong(b[off],   b[off+1], b[off+2], b[off+3],
  @                                         b[off+4], b[off+5], b[off+6], b[off+7]);
  @   ensures \result == Long.BYTES;
  @   signals_only BadCiphertextException;
  @   signals (BadCiphertextException) contentLength_ < 0 && isComplete_ == \old(isComplete_);
  @ also
  @ // case: parse both normally
  @ public behavior
  @   old int nLen = nonceLength_;
  @   requires b != null;
  @   requires nonce_ == null && nonceLength_ > 0 && contentLength_ < 0;
  @   requires off >= 0 && b.length - off >= nonceLength_;
  @   requires b.length - (off + nonceLength_) >= Long.BYTES;
  @   requires nonceLength_ <= Integer.MAX_VALUE - Long.BYTES;
  @   assignable nonce_, contentLength_, isComplete_;
  @   ensures isComplete_ && contentLength_ >= 0;
  @   ensures Arrays.equalArrays(b, off, nonce_, 0, nonceLength_);
  @   ensures contentLength_ == Long.asLong(b[nLen+off],   b[nLen+off+1], b[nLen+off+2],
  @                                         b[nLen+off+3], b[nLen+off+4], b[nLen+off+5],
  @                                         b[nLen+off+6], b[nLen+off+7]);
  @   ensures \result == nonceLength_ + Long.BYTES;
  @   signals_only BadCiphertextException;
  @   signals (BadCiphertextException) (contentLength_ < 0 && isComplete_ == \old(isComplete_)
  @                                     && Arrays.equalArrays(b, off, nonce_, 0, nonceLength_));
  @*/
  public int deserialize(/*@ nullable */ final byte[] b, final int off) {
    if (b == null) {
      return 0;
    }

    // @ assert b != null;
    int parsedBytes = 0;
    try {
      if (nonceLength_ > 0 && nonce_ == null) {
        parsedBytes += parseNonce(b, off + parsedBytes);
      }

      if (contentLength_ < 0) {
        parsedBytes += parseContentLength(b, off + parsedBytes);
      }

      isComplete_ = true;
    } catch (ParseException e) {
      // this results when we do partial parsing and there aren't enough
      // bytes to parse; so just return the bytes parsed thus far.
    }

    return parsedBytes;
  }

  /**
   * Check if this object has all the header fields populated and available for reading.
   *
   * @return true if this object containing the single block header fields is complete; false
   *     otherwise.
   */
  // @ public normal_behavior
  // @   ensures \result == isComplete_;
  // @ pure
  public boolean isComplete() {
    return isComplete_;
  }

  /**
   * Return the nonce set in the single block header.
   *
   * @return the bytes containing the nonce set in the single block header.
   */
  // @ public normal_behavior
  // @   requires nonce_ == null;
  // @   ensures \result == null;
  // @ also public normal_behavior
  // @   requires nonce_ != null;
  // @   ensures \result != null;
  // @   ensures \fresh(\result);
  // @   ensures \result != null;
  // @   ensures \result.length == nonce_.length;
  // @   ensures java.util.Arrays.equalArrays(\result,nonce_);
  // @ pure nullable
  public byte[] getNonce() {
    return nonce_ != null ? nonce_.clone() : null;
  }

  /**
   * Return the content length set in the single block header.
   *
   * @return the content length set in the single block header.
   */
  // @ public normal_behavior
  // @   ensures \result == contentLength_;
  // @ pure
  public long getContentLength() {
    return contentLength_;
  }

  /**
   * Set the length of the nonce used in the encryption of the content stored in the single block.
   *
   * @param nonceLength the length of the nonce used in the encryption of the content stored in the
   *     single block.
   */
  // @ public normal_behavior
  // @   requires nonceLength >= 0;
  // @   assignable nonceLength_;
  // @   ensures nonceLength_ == nonceLength;
  public void setNonceLength(final short nonceLength) {
    nonceLength_ = nonceLength;
  }
}
