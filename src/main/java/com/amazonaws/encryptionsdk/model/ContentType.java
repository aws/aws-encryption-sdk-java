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

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * This enum describes the supported types for storing the encrypted content in the message format.
 * There are two types current currently supported: single block and frames.
 *
 * <p>The single block format stores the encrypted content in a single block wrapped with headers
 * containing the nonce, MAC tag, and the content length.
 *
 * <p>The frame format partitions the encrypted content in multiple frames of a specified frame
 * length. Each frame is wrapped by an header containing the frame sequence number, nonce, and the
 * MAC tag.
 *
 * <p>Format: ContentType(byte value representing the type)
 */
public enum ContentType {
  SINGLEBLOCK(1),
  FRAME(2);

  private final byte value_;

  /**
   * Create a mapping between the ContentType object and its byte value. This is a static method so
   * the map is created when the class is loaded. This enables fast lookups of the ContentType given
   * a value.
   */
  private static final Map<Byte, ContentType> ID_MAPPING = new HashMap<Byte, ContentType>();

  static {
    for (final ContentType s : EnumSet.allOf(ContentType.class)) {
      ID_MAPPING.put(s.value_, s);
    }
  }

  private ContentType(final int value) {
    /*
     * Java reads literals as integers. So we cast the integer value to byte
     * here to avoid doing this in the enum definitions above.
     */
    value_ = (byte) value;
  }

  /**
   * Return the value used to encode this content type object in the ciphertext.
   *
   * @return the byte value used to encode this content type.
   */
  public byte getValue() {
    return value_;
  }

  /**
   * Deserialize the provided byte value by returning the ContentType object representing the byte
   * value.
   *
   * @param value the byte representing the value of the ContentType object.
   * @return the ContentType object representing the byte value.
   */
  public static ContentType deserialize(final byte value) {
    final Byte valueByte = Byte.valueOf(value);
    final ContentType result = ID_MAPPING.get(valueByte);
    return result;
  }
}
