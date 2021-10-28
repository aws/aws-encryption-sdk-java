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
import com.amazonaws.encryptionsdk.exception.ParseException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.PrimitivesParser;
import com.amazonaws.encryptionsdk.internal.Utils;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * This class encapsulates the optional footer information which follows the actual protected
 * content.
 *
 * <p>It contains the following fields in order:
 *
 * <ol>
 *   <li>AuthLength - 2 bytes
 *   <li>MAuth - {@code AuthLength} bytes
 * </ol>
 */
public class CiphertextFooters {
  private int authLength_ = -1;
  private byte[] mAuth_ = null;
  private boolean isComplete_ = false;

  public CiphertextFooters() {
    // Do nothing
  }

  public CiphertextFooters(final byte[] mAuth) {
    final int length = Utils.assertNonNull(mAuth, "mAuth").length;
    if (length < 0 || length > Constants.UNSIGNED_SHORT_MAX_VAL) {
      throw new IllegalArgumentException("Invalid length for mAuth: " + length);
    }
    authLength_ = length;
    mAuth_ = mAuth.clone();
    isComplete_ = true;
  }

  /**
   * Parses the footers from the {@code b} starting at offset {@code off} and returns the number of
   * bytes parsed/consumed.
   */
  public int deserialize(final byte[] b, final int off) throws ParseException {
    if (b == null) {
      return 0;
    }
    int parsedBytes = 0;
    try {
      if (authLength_ < 0) {
        parsedBytes += parseLength(b, off + parsedBytes);
      }
      if (mAuth_ == null) {
        parsedBytes += parseMauth(b, off + parsedBytes);
      }
      isComplete_ = true;
    } catch (ParseException e) {
      // this results when we do partial parsing and there aren't enough
      // bytes to parse; ignore it and return the bytes parsed thus far.
    }
    return parsedBytes;
  }

  public int getAuthLength() {
    return authLength_;
  }

  public byte[] getMAuth() {
    return (mAuth_ != null) ? mAuth_.clone() : null;
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

  public byte[] toByteArray() {
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos)) {
      PrimitivesParser.writeUnsignedShort(dos, authLength_);
      dos.write(mAuth_);
      dos.close();
      baos.close();
      return baos.toByteArray();
    } catch (final IOException ex) {
      throw new AwsCryptoException(ex);
    }
  }

  private int parseLength(final byte[] b, final int off) throws ParseException {
    authLength_ = PrimitivesParser.parseUnsignedShort(b, off);
    return 2;
  }

  private int parseMauth(final byte[] b, final int off) throws ParseException {
    final int len = b.length - off;
    if (len >= authLength_) {
      mAuth_ = Arrays.copyOfRange(b, off, off + authLength_);
      return authLength_;
    } else {
      throw new ParseException(
          "Not enough bytes to parse mAuth, "
              + " needed at least "
              + authLength_
              + " bytes, but only had "
              + len
              + " bytes");
    }
  }
}
