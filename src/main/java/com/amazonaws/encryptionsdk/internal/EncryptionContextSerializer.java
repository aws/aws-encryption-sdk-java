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

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * This class provides methods that serialize and deserialize the encryption context provided as a
 * map containing key-value pairs comprised of strings.
 */
public class EncryptionContextSerializer {
  private EncryptionContextSerializer() {
    // Prevent instantiation
  }

  /**
   * Serialize the encryption context provided as a map containing key-value pairs comprised of
   * strings into a byte array.
   *
   * @param encryptionContext the map containing the encryption context to serialize.
   * @return serialized bytes of the encryption context.
   */
  public static byte[] serialize(Map<String, String> encryptionContext) {
    if (encryptionContext == null) return null;

    if (encryptionContext.size() == 0) {
      return new byte[0];
    }

    // Make sure we don't accidentally overwrite anything.
    encryptionContext = Collections.unmodifiableMap(encryptionContext);

    if (encryptionContext.size() > Short.MAX_VALUE) {
      throw new AwsCryptoException(
          "The number of entries in encryption context exceeds the allowed maximum "
              + Short.MAX_VALUE);
    }

    final ByteBuffer result = ByteBuffer.allocate(Short.MAX_VALUE);
    result.order(ByteOrder.BIG_ENDIAN);
    // write the number of key-value entries first
    result.putShort((short) encryptionContext.size());

    try {
      final CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder();

      // ensure all failures in encoder are reported.
      encoder.onMalformedInput(CodingErrorAction.REPORT);
      encoder.onUnmappableCharacter(CodingErrorAction.REPORT);

      final SortedMap<ByteBuffer, ByteBuffer> binaryEntries =
          new TreeMap<>(new Utils.ComparingByteBuffers());
      for (Entry<String, String> mapEntry : encryptionContext.entrySet()) {
        if (mapEntry.getKey() == null || mapEntry.getValue() == null) {
          throw new AwsCryptoException(
              "All keys and values in encryption context must be non-null.");
        }

        if (mapEntry.getKey().isEmpty() || mapEntry.getValue().isEmpty()) {
          throw new AwsCryptoException(
              "All keys and values in encryption context must be non-empty.");
        }

        final ByteBuffer keyBytes = encoder.encode(CharBuffer.wrap(mapEntry.getKey()));
        final ByteBuffer valueBytes = encoder.encode(CharBuffer.wrap(mapEntry.getValue()));

        // check for duplicate entries.
        if (binaryEntries.put(keyBytes, valueBytes) != null) {
          throw new AwsCryptoException("Encryption context contains duplicate entries.");
        }

        if (keyBytes.limit() > Short.MAX_VALUE || valueBytes.limit() > Short.MAX_VALUE) {
          throw new AwsCryptoException(
              "All keys and values in encryption context must be shorter than " + Short.MAX_VALUE);
        }
      }

      for (final Entry<ByteBuffer, ByteBuffer> entry : binaryEntries.entrySet()) {
        // actual serialization happens here
        result.putShort((short) entry.getKey().limit());
        result.put(entry.getKey());
        result.putShort((short) entry.getValue().limit());
        result.put(entry.getValue());
      }

      // get and return the bytes that have been serialized
      Utils.flip(result);
      final byte[] encryptionContextBytes = new byte[result.limit()];
      result.get(encryptionContextBytes);

      return encryptionContextBytes;
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException(
          "Encryption context contains an invalid unicode character");
    } catch (BufferOverflowException e) {
      throw new AwsCryptoException(
          "The number of bytes in encryption context exceeds the allowed maximum "
              + Short.MAX_VALUE,
          e);
    }
  }

  /**
   * Deserialize the provided byte array into a map containing key-value pairs comprised of strings.
   *
   * @param b the bytes to deserialize into a map representing the encryption context.
   * @return the map containing key-value pairs comprised of strings.
   */
  public static Map<String, String> deserialize(final byte[] b) {
    try {
      if (b == null) {
        return null;
      }

      if (b.length == 0) {
        return (Collections.<String, String>emptyMap());
      }

      final ByteBuffer encryptionContextBytes = ByteBuffer.wrap(b);

      // retrieve the number of entries first
      final int entryCount = encryptionContextBytes.getShort();
      if (entryCount <= 0 || entryCount > Short.MAX_VALUE) {
        throw new AwsCryptoException(
            "The number of entries in encryption context must be greater than 0 and smaller than "
                + Short.MAX_VALUE);
      }

      final CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();

      // ensure all failures in decoder are reported.
      decoder.onMalformedInput(CodingErrorAction.REPORT);
      decoder.onUnmappableCharacter(CodingErrorAction.REPORT);

      final Map<String, String> result = new HashMap<>(entryCount);
      for (int i = 0; i < entryCount; i++) {
        // retrieve key
        final int keyLen = encryptionContextBytes.getShort();
        if (keyLen <= 0 || keyLen > Short.MAX_VALUE) {
          throw new AwsCryptoException(
              "Key length must be greater than 0 and smaller than " + Short.MAX_VALUE);
        }

        final ByteBuffer keyBytes = encryptionContextBytes.slice();
        Utils.limit(keyBytes, keyLen);
        Utils.position(encryptionContextBytes, encryptionContextBytes.position() + keyLen);

        final int valueLen = encryptionContextBytes.getShort();
        if (valueLen <= 0 || valueLen > Short.MAX_VALUE) {
          throw new AwsCryptoException(
              "Value length must be greater than 0 and smaller than " + Short.MAX_VALUE);
        }

        // retrieve value
        final ByteBuffer valueBytes = encryptionContextBytes.slice();
        Utils.limit(valueBytes, valueLen);
        Utils.position(encryptionContextBytes, encryptionContextBytes.position() + valueLen);

        final CharBuffer keyChars = decoder.decode(keyBytes);
        final CharBuffer valueChars = decoder.decode(valueBytes);

        // check for duplicate entries.
        if (result.put(keyChars.toString(), valueChars.toString()) != null) {
          throw new AwsCryptoException("Encryption context contains duplicate entries.");
        }
      }

      return result;
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException(
          "Encryption context contains an invalid unicode character");
    } catch (BufferUnderflowException e) {
      throw new AwsCryptoException("Invalid encryption context. Expected more bytes.", e);
    }
  }
}
