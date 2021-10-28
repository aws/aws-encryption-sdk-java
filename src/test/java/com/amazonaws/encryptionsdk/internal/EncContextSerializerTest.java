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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.Test;

public class EncContextSerializerTest {

  @Test
  public void nullContext() {
    final byte[] ctxBytes = EncryptionContextSerializer.serialize(null);
    final Map<String, String> result = EncryptionContextSerializer.deserialize(ctxBytes);
    assertEquals(null, result);
  }

  @Test
  public void emptyContext() {
    testMap(Collections.<String, String>emptyMap());
  }

  @Test
  public void singletonContext() {
    testMap(Collections.singletonMap("Alice:", "trusts Bob"));
  }

  @Test
  public void contextOrdering() throws Exception {
    // Context keys should be sorted by unsigned byte order
    Map<String, String> map = new HashMap<>();

    map.put("\0", "\0");
    map.put("\u0081", "\u0081"); // 0xC2 0x81 in UTF8

    assertArrayEquals(
        new byte[] {
          0,
          2,
          // "\0"
          0,
          1,
          (byte) '\0',
          // "\0"
          0,
          1,
          (byte) '\0',
          // "\u0081"
          0,
          2,
          (byte) 0xC2,
          (byte) 0x81,
          // "\u0081"
          0,
          2,
          (byte) 0xC2,
          (byte) 0x81,
        },
        EncryptionContextSerializer.serialize(map));
  }

  @Test
  public void smallContext() {
    final Map<String, String> map = new HashMap<String, String>();
    map.put("Alice:", "trusts Bob");
    map.put("Bob:", "trusts Trent");
    testMap(map);
  }

  @Test
  public void largeContext() {
    final int size = 100;
    final Map<String, String> ctx = new HashMap<String, String>(size);
    for (int x = 0; x < size; x++) {
      ctx.put(UUID.randomUUID().toString(), UUID.randomUUID().toString());
    }
    testMap(ctx);
  }

  @Test(expected = AwsCryptoException.class)
  public void overlyLargeContext() {
    final int size = Short.MAX_VALUE;
    final Map<String, String> ctx = new HashMap<String, String>(size);
    // we want to be at least 1 over the (max) size.
    for (int x = 0; x <= size; x++) {
      ctx.put(UUID.randomUUID().toString(), UUID.randomUUID().toString());
    }
    testMap(ctx);
  }

  @Test(expected = AwsCryptoException.class)
  public void overlyLargeKey() {
    final int size = 10;
    final Map<String, String> ctx = new HashMap<String, String>(size);
    final char[] keyChars = new char[Short.MAX_VALUE + 1];
    final String key = new String(keyChars);

    for (int x = 0; x < size; x++) {
      ctx.put(key, UUID.randomUUID().toString());
    }
    testMap(ctx);
  }

  @Test(expected = AwsCryptoException.class)
  public void overlyLargeValue() {
    final int size = 10;
    final Map<String, String> ctx = new HashMap<String, String>(size);
    final char[] valueChars = new char[Short.MAX_VALUE + 1];
    final String value = new String(valueChars);

    for (int x = 0; x < size; x++) {
      ctx.put(UUID.randomUUID().toString(), value);
    }
    testMap(ctx);
  }

  @Test(expected = AwsCryptoException.class)
  public void overlyLargeContextBytes() {
    final char[] keyChars = new char[Short.MAX_VALUE];
    final String key = new String(keyChars);
    final char[] valueChars = new char[Short.MAX_VALUE];
    final String value = new String(valueChars);

    testMap(Collections.singletonMap(key, value));
  }

  @Test(expected = IllegalArgumentException.class)
  public void contextWithBadUnicodeKey() {
    final StringBuilder invalidString = new StringBuilder("Valid text");
    // Loop over invalid unicode codepoints
    for (int x = 0xd800; x <= 0xdfff; x++) {
      invalidString.appendCodePoint(x);
    }
    testMap(Collections.singletonMap(invalidString.toString(), "Valid value"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void contextWithBadUnicodeValue() {
    final StringBuilder invalidString = new StringBuilder("Base valid text");
    for (int x = 0xd800; x <= 0xdfff; x++) { // Invalid unicode codepoints
      invalidString.appendCodePoint(x);
    }
    testMap(Collections.singletonMap("Valid key", invalidString.toString()));
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithEmptyKey() {
    testMap(Collections.singletonMap("", "Value for empty key"));
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithEmptyValue() {
    testMap(Collections.singletonMap("Key for empty value", ""));
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithEmptyKeyAndValue() {
    testMap(Collections.singletonMap("", ""));
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithNullKey() {
    testMap(Collections.singletonMap((String) null, "value for null key"));
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithNullValue() {
    testMap(Collections.singletonMap("Key for null value", (String) null));
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithNullKeyAndValue() {
    testMap(Collections.singletonMap((String) null, (String) null));
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithLargeKey() {
    final Map<String, String> ctx = new HashMap<String, String>();
    ctx.put("Alice:", "trusts Bob");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);

    // Pull out entry count to move to key pos
    ctxBuff.getShort();
    // Overwrite key length
    ctxBuff.putShort((short) Constants.UNSIGNED_SHORT_MAX_VAL);

    // The actual call which should fail
    EncryptionContextSerializer.deserialize(ctxBuff.array());
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithShortKey() {
    final Map<String, String> ctx = new HashMap<String, String>();
    ctx.put("Alice:", "trusts Bob");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);

    // Pull out entry count to move to key pos
    ctxBuff.getShort();
    // Overwrite key length with 0
    ctxBuff.putShort((short) 0);

    // The actual call which should fail
    EncryptionContextSerializer.deserialize(ctxBuff.array());
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithNegativeKey() {
    final Map<String, String> ctx = new HashMap<String, String>();
    ctx.put("Alice:", "trusts Bob");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);

    // Pull out entry count to move to key pos
    ctxBuff.getShort();
    // Overwrite key length with -1.
    ctxBuff.putShort((short) -1);

    // The actual call which should fail
    EncryptionContextSerializer.deserialize(ctxBuff.array());
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithLargeValue() {
    final Map<String, String> ctx = new HashMap<String, String>();
    ctx.put("Alice:", "trusts Bob");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);

    // Pull out entry count to move to key pos
    ctxBuff.getShort();

    // Pull out key length and bytes.
    final short keyLen = ctxBuff.getShort();
    final byte[] key = new byte[keyLen];
    ctxBuff.get(key);

    // Overwrite value length
    ctxBuff.putShort((short) Constants.UNSIGNED_SHORT_MAX_VAL);

    // The actual call which should fail
    EncryptionContextSerializer.deserialize(ctxBuff.array());
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithShortValue() {
    final Map<String, String> ctx = new HashMap<String, String>();
    ctx.put("Alice:", "trusts Bob");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);

    // Pull out entry count to move to key pos
    ctxBuff.getShort();

    // Pull out key length and bytes.
    final short keyLen = ctxBuff.getShort();
    final byte[] key = new byte[keyLen];
    ctxBuff.get(key);

    // Overwrite value length
    ctxBuff.putShort((short) 0);

    // The actual call which should fail
    EncryptionContextSerializer.deserialize(ctxBuff.array());
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithNegativeValue() {
    final Map<String, String> ctx = new HashMap<String, String>();
    ctx.put("Alice:", "trusts Bob");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);

    // Pull out entry count to move to key pos
    ctxBuff.getShort();

    // Pull out key length and bytes.
    final short keyLen = ctxBuff.getShort();
    final byte[] key = new byte[keyLen];
    ctxBuff.get(key);

    // Overwrite value length
    ctxBuff.putShort((short) -1);

    // The actual call which should fail
    EncryptionContextSerializer.deserialize(ctxBuff.array());
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithNegativeCount() {
    final Map<String, String> ctx = new HashMap<String, String>();
    ctx.put("Alice:", "trusts Bob");
    ctx.put("Bob:", "trusts Trent");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);

    // Overwrite entry count
    ctxBuff.putShort((short) -1);

    EncryptionContextSerializer.deserialize(ctxBuff.array());
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithZeroCount() {
    final Map<String, String> ctx = new HashMap<String, String>();
    ctx.put("Alice:", "trusts Bob");
    ctx.put("Bob:", "trusts Trent");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);

    // Overwrite entry count
    ctxBuff.putShort((short) 0);

    EncryptionContextSerializer.deserialize(ctxBuff.array());
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithInvalidCount() {
    final Map<String, String> ctx = new HashMap<String, String>();
    ctx.put("Alice:", "trusts Bob");
    ctx.put("Bob:", "trusts Trent");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);

    // Overwrite count with more than what we have
    ctxBuff.putShort((short) 100);

    // The actual call which should fail
    EncryptionContextSerializer.deserialize(ctxBuff.array());
  }

  @Test(expected = IllegalArgumentException.class)
  public void contextWithInvalidCharacters() {
    final Map<String, String> ctx = new HashMap<String, String>();
    ctx.put("Alice:", "trusts Bob");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);

    // Pull out entry count to move to key pos
    ctxBuff.getShort();

    // Pull out key length and bytes.
    final short keyLen = ctxBuff.getShort();
    ctxBuff.mark();

    final byte[] key = new byte[keyLen];
    ctxBuff.get(key);

    // set the first two bytes of the key to an invalid
    // unicode character: 0xd800.
    key[0] = 0x0;
    key[1] = (byte) 0xd8;

    ctxBuff.reset();
    ctxBuff.put(key);

    // The actual call which should fail
    EncryptionContextSerializer.deserialize(ctxBuff.array());
  }

  @Test(expected = AwsCryptoException.class)
  public void contextWithDuplicateEntries() {
    final Map<String, String> ctx = Collections.singletonMap("Alice:", "trusts Bob");

    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final ByteBuffer ctxBuff = ByteBuffer.wrap(ctxBytes);
    // Don't duplicate the entry count
    final ByteBuffer dupCtxBuff = ByteBuffer.allocate((2 * ctxBytes.length) - 2);

    // Set to 2 entries
    dupCtxBuff.putShort((short) 2);

    // Pull out entry count to move to key pos
    ctxBuff.getShort();
    // From here to the end is a single entry, copy it
    final byte[] entry = new byte[ctxBuff.remaining()];
    ctxBuff.get(entry);

    dupCtxBuff.put(entry);
    dupCtxBuff.put(entry);

    EncryptionContextSerializer.deserialize(dupCtxBuff.array());
  }

  private void testMap(final Map<String, String> ctx) {
    final byte[] ctxBytes = EncryptionContextSerializer.serialize(Collections.unmodifiableMap(ctx));
    final Map<String, String> result = EncryptionContextSerializer.deserialize(ctxBytes);
    assertEquals(ctx, result);
  }
}
