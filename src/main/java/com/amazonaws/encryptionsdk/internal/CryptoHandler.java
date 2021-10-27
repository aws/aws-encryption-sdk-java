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

/**
 * This interface defines the contract for the implementation of encryption and decryption handlers
 * in this library.
 *
 * <p>The implementations of this interface provided in this package currently process bytes in a
 * single block mode (where all input data is processed in entirety, or in a framing mode (where
 * data is processed incrementally in chunks).
 */
public interface CryptoHandler {
  /**
   * Process a block of bytes from {@code in} putting the result into {@code out}.
   *
   * @param in the input byte array.
   * @param inOff the offset into the {@code in} array where the data to be processed starts.
   * @param inLen the number of bytes to be processed.
   * @param out the output buffer the processed bytes go into.
   * @param outOff the offset into the output byte array the processed data starts at.
   * @return the number of bytes written to {@code out} and the number of bytes parsed.
   */
  ProcessingSummary processBytes(
      final byte[] in, final int inOff, final int inLen, byte[] out, final int outOff);

  /**
   * Finish processing of the bytes.
   *
   * @param out the output buffer for copying any remaining output data.
   * @param outOff offset into {@code out} to start copying the output data.
   * @return number of bytes written into {@code out}.
   */
  int doFinal(final byte[] out, final int outOff);

  /**
   * Return the size of the output buffer required for a {@link #processBytes(byte[], int, int,
   * byte[], int)} plus a {@link #doFinal(byte[], int)} call with an input of {@code inLen} bytes.
   *
   * <p>Note this method is allowed to return an estimation of the output size that is
   * <i>greater</i> than the actual size of the output. Returning an estimate that is lesser than
   * the actual size of the output will result in underflow exceptions.
   *
   * @param inLen the length of the input.
   * @return the space required to accommodate a call to processBytes and {@link #doFinal(byte[],
   *     int)} with an input of size {@code inLen} bytes.
   */
  int estimateOutputSize(final int inLen);

  /**
   * Return the size of the output buffer required for a call to {@link #processBytes(byte[], int,
   * int, byte[], int)}.
   *
   * <p>Note this method is allowed to return an estimation of the output size that is
   * <i>greater</i> than the actual size of the output. Returning an estimate that is lesser than
   * the actual size of the output will result in underflow exceptions.
   *
   * @param inLen the length of the input.
   * @return the space required to accommodate a call to {@link #processBytes(byte[], int, int,
   *     byte[], int)} with an input of size {@code inLen} bytes.
   */
  int estimatePartialOutputSize(final int inLen);

  /**
   * Return the size of the output buffer required for a call to {@link #doFinal(byte[], int)}.
   *
   * <p>Note this method is allowed to return an estimation of the output size that is
   * <i>greater</i> than the actual size of the output. Returning an estimate that is lesser than
   * the actual size of the output will result in underflow exceptions.
   *
   * @return the space required to accomodate a call to {@link #doFinal(byte[], int)}
   */
  int estimateFinalOutputSize();

  /**
   * For decrypt and parsing flows returns {@code true} when this has handled as many bytes as it
   * can. This usually means that it has reached the end of an object, file, or other delimited
   * stream.
   */
  boolean isComplete();
}
