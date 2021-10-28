// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

/** Unit tests for {@link Utils} */
public class UtilsTest {
  @Test
  public void compareObjectIdentityTest() {
    assertNotEquals(0, Utils.compareObjectIdentity(null, new Object()));
    assertNotEquals(0, Utils.compareObjectIdentity(new Object(), null));

    assertEquals(0, Utils.compareObjectIdentity(Utils.class, Utils.class));
    assertNotEquals(0, Utils.compareObjectIdentity(new Object(), new Object()));
  }

  @Test
  public void compareObjectIdentity_handlesHashCodeCollisions() {
    // With this large of an array, it is overwhelmingly likely that we will see two objects with
    // identical
    // identity hash codes.
    Object[] testArray = new Object[512_000];

    for (int i = 0; i < testArray.length; i++) {
      testArray[i] = new Object();
    }

    java.util.Arrays.sort(testArray, Utils::compareObjectIdentity);

    // Verify that we do not have any objects that are equal (compare to zero) in the array.
    // We know the primary sort is by hashcode, so we'll just do exhaustive comparison within each
    // hashcode.

    boolean sawCollison = false;
    for (int i = 0; i < testArray.length; i++) {
      int hashCode = System.identityHashCode(testArray[i]);

      int endOfHashGroup = i;
      while (endOfHashGroup + 1 < testArray.length
          && System.identityHashCode(testArray[endOfHashGroup + 1]) == hashCode) {
        endOfHashGroup++;
      }

      if (i != endOfHashGroup) {
        sawCollison = true;
      }

      for (int a = i; a <= endOfHashGroup; a++) {
        for (int b = a + 1; b <= endOfHashGroup; b++) {
          if (a != b) {
            assertNotEquals(0, Utils.compareObjectIdentity(a, b));
          }
        }
      }
    }

    assertTrue(sawCollison);
  }

  @Test
  public void testSaturatingAdd() {
    assertEquals(0, Utils.saturatingAdd(0, 0));
    assertEquals(2, Utils.saturatingAdd(1, 1));
    assertEquals(-2, Utils.saturatingAdd(-1, -1));
    assertEquals(0, Utils.saturatingAdd(-1, +1));
    assertEquals(0, Utils.saturatingAdd(+1, -1));

    assertEquals(Long.MIN_VALUE, Utils.saturatingAdd(Long.MIN_VALUE + 1, -2));
    assertEquals(Long.MAX_VALUE, Utils.saturatingAdd(Long.MAX_VALUE - 1, +2));
    assertEquals(Long.MAX_VALUE, Utils.saturatingAdd(Long.MAX_VALUE, Long.MAX_VALUE));
    assertEquals(Long.MIN_VALUE, Utils.saturatingAdd(Long.MIN_VALUE, Long.MIN_VALUE));
  }

  /** Basic sanity check for our Base64 helper methods. */
  @Test
  public void base64empty() {
    assertEquals("", Utils.encodeBase64String(new byte[] {}));
    assertArrayEquals(new byte[] {}, Utils.decodeBase64String(""));
  }

  /** Basic sanity check for our Base64 helper methods. */
  @Test
  public void base64something() {
    byte[] data = "Lorem ipsum dolor sit amet".getBytes(StandardCharsets.UTF_8);
    String encoded = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ=";
    assertEquals(encoded, Utils.encodeBase64String(data));
    assertArrayEquals(data, Utils.decodeBase64String(encoded));
  }

  @Test
  public void testBigIntegerToByteArray() {
    byte[] bytes = new byte[] {23, 47, 126, -42, 34};

    assertArrayEquals(
        new byte[] {0, 0, 0, 23, 47, 126, -42, 34},
        Utils.bigIntegerToByteArray(new BigInteger(bytes), 8));
    assertArrayEquals(
        new byte[] {23, 47, 126, -42, 34}, Utils.bigIntegerToByteArray(new BigInteger(bytes), 5));

    bytes = new byte[] {0, -47, 126, -42, 34};

    assertArrayEquals(
        new byte[] {-47, 126, -42, 34}, Utils.bigIntegerToByteArray(new BigInteger(bytes), 4));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testBigIntegerToByteArray_InvalidLength() {
    byte[] bytes = new byte[] {0, -47, 126, -42, 34};

    assertArrayEquals(bytes, Utils.bigIntegerToByteArray(new BigInteger(bytes), 3));
  }

  @Test
  public void testArrayPrefixEquals() {
    byte[] a = new byte[] {10, 11, 12, 13, 14, 15};
    byte[] b = new byte[] {10, 11, 12, 13, 20, 21, 22};

    assertFalse(Utils.arrayPrefixEquals(null, b, 4));
    assertFalse(Utils.arrayPrefixEquals(a, null, 4));
    assertFalse(Utils.arrayPrefixEquals(a, b, a.length + 1));
    assertTrue(Utils.arrayPrefixEquals(a, b, 4));
    assertFalse(Utils.arrayPrefixEquals(a, b, 5));
  }
}
