/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Exposes header information of ciphertexts to make it easier to inspect the algorithm, keys, and
 * encryption context prior to decryption.
 *
 * <p>Please note that the class does <em>not</em> make defensive copies.
 */
public class ParsedCiphertext extends CiphertextHeaders {
  private final byte[] ciphertext_;
  private final int offset_;

  /**
   * Parses {@code ciphertext}. Please note that this does <em>not</em> make a defensive copy of
   * {@code ciphertext} and that any changes made to the backing array will be reflected here as
   * well.
   *
   * @param ciphertext The ciphertext to parse
   * @param maxEncryptedDataKeys The maximum number of encrypted data keys to parse. Zero indicates
   *     no maximum.
   */
  public ParsedCiphertext(final byte[] ciphertext, final int maxEncryptedDataKeys) {
    ciphertext_ = Utils.assertNonNull(ciphertext, "ciphertext");
    offset_ = deserialize(ciphertext_, 0, maxEncryptedDataKeys);
    if (!this.isComplete()) {
      throw new BadCiphertextException("Incomplete ciphertext.");
    }
  }

  /**
   * Parses {@code ciphertext} without enforcing a max EDK count. Please note that this does
   * <em>not</em> make a defensive copy of {@code ciphertext} and that any changes made to the
   * backing array will be reflected here as well.
   */
  public ParsedCiphertext(final byte[] ciphertext) {
    this(ciphertext, CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
  }

  /**
   * Returns the raw ciphertext backing this object. This is <em>not</em> a defensive copy and so
   * must not be modified by callers.
   */
  @SuppressFBWarnings("EI_EXPOSE_REP")
  public byte[] getCiphertext() {
    return ciphertext_;
  }

  /** The offset at which the first non-header byte in {@code ciphertext} is located. */
  public int getOffset() {
    return offset_;
  }
}
