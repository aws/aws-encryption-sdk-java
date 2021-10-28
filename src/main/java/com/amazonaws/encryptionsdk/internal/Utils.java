// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Comparator;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.util.encoders.Base64;

/** Internal utility methods. */
public final class Utils {
  // SecureRandom objects can both be expensive to initialize and incur synchronization costs.
  // This allows us to minimize both initializations and keep SecureRandom usage thread local
  // to avoid lock contention.
  private static final ThreadLocal<SecureRandom> LOCAL_RANDOM =
      new ThreadLocal<SecureRandom>() {
        @Override
        protected SecureRandom initialValue() {
          final SecureRandom rnd = new SecureRandom();
          rnd.nextBoolean(); // Force seeding
          return rnd;
        }
      };

  private Utils() {
    // Prevent instantiation
  }

  /*
   * In some areas we need to be able to assign a total order over Java objects - generally with some primary sort,
   * but we need a fallback sort that always works in order to ensure that we don't falsely claim objects A and B
   * are equal just because the primary sort declares them to have equal rank.
   *
   * To do this, we'll define a fallback sort that assigns an arbitrary order to all objects. This order is
   * implemented by first comparing hashcode, and in the rare case where we are asked to compare two objects with
   * equal hashcode, we explicitly assign an index to them - using a WeakHashMap to track this index - and sort
   * based on this index.
   */
  private static AtomicLong FALLBACK_COUNTER = new AtomicLong(0);
  private static WeakHashMap<Object, Long> FALLBACK_COMPARATOR_MAP = new WeakHashMap<>();

  private static synchronized long getFallbackObjectId(Object object) {
    return FALLBACK_COMPARATOR_MAP.computeIfAbsent(
        object, ignored -> FALLBACK_COUNTER.incrementAndGet());
  }

  /**
   * Provides an <i>arbitrary</i> but consistent total ordering over all objects. This comparison
   * function will return 0 if and only if a == b, and otherwise will return arbitrarily either -1
   * or 1, but will do so in a way that results in a consistent total order.
   *
   * @param a
   * @param b
   * @return -1 or 1 (consistently) if a != b; 0 if a == b.
   */
  public static int compareObjectIdentity(Object a, Object b) {
    if (a == b) {
      return 0;
    }

    if (a == null) {
      return -1;
    }

    if (b == null) {
      return 1;
    }

    int hashCompare = Integer.compare(System.identityHashCode(a), System.identityHashCode(b));
    if (hashCompare != 0) {
      return hashCompare;
    }

    // Unfortunately these objects have identical hashcodes, so we need to find some other way to
    // compare them.
    // We'll do this by mapping them to an incrementing counter, and comparing their assigned IDs
    // instead.
    int fallbackCompare = Long.compare(getFallbackObjectId(a), getFallbackObjectId(b));
    if (fallbackCompare == 0) {
      throw new AssertionError("Failed to assign unique order to objects");
    }

    return fallbackCompare;
  }

  public static long saturatingAdd(long a, long b) {
    long r = a + b;

    if (a > 0 && b > 0 && r < a) {
      return Long.MAX_VALUE;
    }

    if (a < 0 && b < 0 && r > a) {
      return Long.MIN_VALUE;
    }

    // If the signs between a and b differ, overflow is impossible.

    return r;
  }

  /**
   * Comparator that performs a lexicographical comparison of byte arrays, treating them as
   * unsigned.
   */
  public static class ComparingByteArrays implements Comparator<byte[]>, Serializable {
    // We don't really need to be serializable, but it doesn't hurt, and FindBugs gets annoyed if
    // we're not.
    private static final long serialVersionUID = 0xdf641037ffe509e2L;

    @Override
    public int compare(byte[] o1, byte[] o2) {
      return new ComparingByteBuffers().compare(ByteBuffer.wrap(o1), ByteBuffer.wrap(o2));
    }
  }

  public static class ComparingByteBuffers implements Comparator<ByteBuffer>, Serializable {
    private static final long serialVersionUID = 0xa3c4a7300fbbf043L;

    @Override
    public int compare(ByteBuffer o1, ByteBuffer o2) {
      o1 = o1.slice();
      o2 = o2.slice();

      int commonLength = Math.min(o1.remaining(), o2.remaining());

      for (int i = 0; i < commonLength; i++) {
        // Perform zero-extension as we want to treat the bytes as unsigned
        int v1 = o1.get(i) & 0xFF;
        int v2 = o2.get(i) & 0xFF;

        if (v1 != v2) {
          return v1 - v2;
        }
      }

      // The longer buffer is bigger (0x00 comes after end-of-buffer)
      return o1.remaining() - o2.remaining();
    }
  }

  /**
   * Throws {@link NullPointerException} with message {@code paramName} if {@code object} is null.
   *
   * @param object value to be null-checked
   * @param paramName message for the potential {@link NullPointerException}
   * @return {@code object}
   * @throws NullPointerException if {@code object} is null
   */
  public static <T> T assertNonNull(final T object, final String paramName)
      throws NullPointerException {
    if (object == null) {
      throw new NullPointerException(paramName + " must not be null");
    }
    return object;
  }

  /**
   * Returns a possibly truncated version of {@code arr} which is guaranteed to be exactly {@code
   * len} elements long. If {@code arr} is already exactly {@code len} elements long, then {@code
   * arr} is returned without copy or modification. If {@code arr} is longer than {@code len}, then
   * a truncated copy is returned. If {@code arr} is shorter than {@code len} then this throws an
   * {@link IllegalArgumentException}.
   */
  public static byte[] truncate(final byte[] arr, final int len) throws IllegalArgumentException {
    if (arr.length == len) {
      return arr;
    } else if (arr.length > len) {
      return Arrays.copyOf(arr, len);
    } else {
      throw new IllegalArgumentException("arr is not at least " + len + " elements long");
    }
  }

  public static SecureRandom getSecureRandom() {
    return LOCAL_RANDOM.get();
  }

  /**
   * Generate the AAD bytes to use when encrypting/decrypting content. The generated AAD is a block
   * of bytes containing the provided message identifier, the string identifier, the sequence
   * number, and the length of the content.
   *
   * @param messageId the unique message identifier for the ciphertext.
   * @param idString the string describing the type of content processed.
   * @param seqNum the sequence number.
   * @param len the length of the content.
   * @return the bytes containing the generated AAD.
   */
  static byte[] generateContentAad(
      final byte[] messageId, final String idString, final int seqNum, final long len) {
    final byte[] idBytes = idString.getBytes(StandardCharsets.UTF_8);
    final int aadLen =
        messageId.length + idBytes.length + Integer.SIZE / Byte.SIZE + Long.SIZE / Byte.SIZE;
    final ByteBuffer aad = ByteBuffer.allocate(aadLen);

    aad.put(messageId);
    aad.put(idBytes);
    aad.putInt(seqNum);
    aad.putLong(len);

    return aad.array();
  }

  static IllegalArgumentException cannotBeNegative(String field) {
    return new IllegalArgumentException(field + " cannot be negative");
  }

  /**
   * Equivalent to calling {@link ByteBuffer#flip()} but in a manner which is safe when compiled on
   * Java 9 or newer but used on Java 8 or older.
   */
  public static ByteBuffer flip(final ByteBuffer buff) {
    ((Buffer) buff).flip();
    return buff;
  }

  /**
   * Equivalent to calling {@link ByteBuffer#clear()} but in a manner which is safe when compiled on
   * Java 9 or newer but used on Java 8 or older.
   */
  public static ByteBuffer clear(final ByteBuffer buff) {
    ((Buffer) buff).clear();
    return buff;
  }

  /**
   * Equivalent to calling {@link ByteBuffer#position(int)} but in a manner which is safe when
   * compiled on Java 9 or newer but used on Java 8 or older.
   */
  public static ByteBuffer position(final ByteBuffer buff, final int newPosition) {
    ((Buffer) buff).position(newPosition);
    return buff;
  }

  /**
   * Equivalent to calling {@link ByteBuffer#limit(int)} but in a manner which is safe when compiled
   * on Java 9 or newer but used on Java 8 or older.
   */
  public static ByteBuffer limit(final ByteBuffer buff, final int newLimit) {
    ((Buffer) buff).limit(newLimit);
    return buff;
  }

  /**
   * Takes a Base64-encoded String, decodes it, and returns contents as a byte array.
   *
   * @param encoded Base64 encoded String
   * @return decoded data as a byte array
   */
  public static byte[] decodeBase64String(final String encoded) {
    return encoded.isEmpty() ? ArrayUtils.EMPTY_BYTE_ARRAY : Base64.decode(encoded);
  }

  /**
   * Takes data in a byte array, encodes them in Base64, and returns the result as a String.
   *
   * @param data The data to encode.
   * @return Base64 string that encodes the {@code data}.
   */
  public static String encodeBase64String(final byte[] data) {
    return Base64.toBase64String(data);
  }

  /**
   * Removes the leading zero sign byte from the byte array representation of a BigInteger (if
   * present) and left pads with zeroes to produce a byte array of the given length.
   *
   * @param bigInteger The BigInteger to convert to a byte array
   * @param length The length of the byte array, must be at least as long as the BigInteger byte
   *     array without the sign byte
   * @return The byte array
   */
  public static byte[] bigIntegerToByteArray(final BigInteger bigInteger, final int length) {
    byte[] rawBytes = bigInteger.toByteArray();
    // If rawBytes is already the correct length, return it.
    if (rawBytes.length == length) {
      return rawBytes;
    }

    // If we're exactly one byte too large, but we have a leading zero byte, remove it and return.
    if (rawBytes.length == length + 1 && rawBytes[0] == 0) {
      return Arrays.copyOfRange(rawBytes, 1, rawBytes.length);
    }

    if (rawBytes.length > length) {
      throw new IllegalArgumentException(
          "Length must be at least as long as the BigInteger byte array "
              + "without the sign byte");
    }

    final byte[] paddedResult = new byte[length];
    System.arraycopy(rawBytes, 0, paddedResult, length - rawBytes.length, rawBytes.length);
    return paddedResult;
  }

  /**
   * Returns true if the prefix of the given length for the input arrays are equal. This method will
   * return as soon as the first difference is found, and is thus not constant-time.
   *
   * @param a The first array.
   * @param b The second array.
   * @param length The length of the prefix to compare.
   * @return True if the prefixes are equal, false otherwise.
   */
  public static boolean arrayPrefixEquals(final byte[] a, final byte[] b, final int length) {
    if (a == null || b == null || a.length < length || b.length < length) {
      return false;
    }
    for (int x = 0; x < length; x++) {
      if (a[x] != b[x]) {
        return false;
      }
    }
    return true;
  }
}
