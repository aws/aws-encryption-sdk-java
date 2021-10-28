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

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import org.junit.Test;

public class PrimitivesParserTest {

  @Test
  public void testParseLong() throws IOException {
    final long[] tests =
        new long[] {
          Long.MIN_VALUE, Long.MAX_VALUE, -1, 0, 1, Long.MIN_VALUE + 1, Long.MAX_VALUE - 1
        };
    for (long x : tests) {
      try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
          final DataOutputStream dos = new DataOutputStream(baos)) {
        dos.writeLong(x);
        dos.close();
        assertEquals(x, PrimitivesParser.parseLong(baos.toByteArray(), 0));
      }
    }
  }

  @Test
  public void testParseInt() throws IOException {
    final int[] tests =
        new int[] {
          Integer.MIN_VALUE,
          Integer.MAX_VALUE,
          -1,
          0,
          1,
          Integer.MIN_VALUE + 1,
          Integer.MAX_VALUE - 1
        };
    for (int x : tests) {
      try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
          final DataOutputStream dos = new DataOutputStream(baos)) {
        dos.writeInt(x);
        dos.close();
        assertEquals(x, PrimitivesParser.parseInt(baos.toByteArray(), 0));
      }
    }
  }

  @Test
  public void testParseShort() throws IOException {
    for (int x = Short.MIN_VALUE; x < Short.MAX_VALUE; x++) {
      try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
          final DataOutputStream dos = new DataOutputStream(baos)) {
        dos.writeShort(x);
        dos.close();
        assertEquals((short) x, PrimitivesParser.parseShort(baos.toByteArray(), 0));
      }
    }
  }

  @Test
  public void testParseUnsignedShort() throws IOException {
    for (int x = 0; x < Constants.UNSIGNED_SHORT_MAX_VAL; x++) {
      try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
          final DataOutputStream dos = new DataOutputStream(baos)) {
        PrimitivesParser.writeUnsignedShort(dos, x);
        assertEquals(x, PrimitivesParser.parseUnsignedShort(baos.toByteArray(), 0));
      }
    }
  }

  @Test
  public void testParseByte() throws IOException {
    for (int x = Byte.MIN_VALUE; x < Byte.MAX_VALUE; x++) {
      try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
          final DataOutputStream dos = new DataOutputStream(baos)) {
        dos.writeByte(x);
        dos.close();
        assertEquals((byte) x, PrimitivesParser.parseByte(baos.toByteArray(), 0));
      }
    }
  }
}
