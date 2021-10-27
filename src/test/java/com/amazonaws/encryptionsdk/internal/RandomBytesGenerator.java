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

import java.security.SecureRandom;

public class RandomBytesGenerator {
  private static final SecureRandom RND = new SecureRandom();

  /* Some Providers (such as the FIPS certified Bouncy Castle) enforce a
   * maximum number of bytes that may be requested from SecureRandom. If
   * the requested len is larger than this value, the Secure Random will
   * be called multiple times to achieve the requested total length. */
  private static final int MAX_BYTES = 1 << 15;

  /**
   * Generates a byte array of random data of the given length.
   *
   * @param len The length of the byte array.
   * @return The byte array.
   */
  public static byte[] generate(final int len) {
    final byte[] result = new byte[len];
    int bytesGenerated = 0;

    while (bytesGenerated < len) {
      final int requestSize = Math.min(MAX_BYTES, len - bytesGenerated);
      final byte[] request = new byte[requestSize];
      RND.nextBytes(request);
      System.arraycopy(request, 0, result, bytesGenerated, requestSize);
      bytesGenerated += requestSize;
    }

    return result;
  }
}
