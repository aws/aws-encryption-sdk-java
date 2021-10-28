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
 * This enum describes the supported types of ciphertext in this library.
 *
 * <p>Format: CiphertextType(byte value representing the type)
 */
public enum CiphertextType {
  CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA(128);

  private final byte value_;

  /**
   * Create a mapping between the CiphertextType object and its byte value. This is a static method
   * so the map is created when the class is loaded. This enables fast lookups of the CiphertextType
   * given a value.
   */
  private static final Map<Byte, CiphertextType> ID_MAPPING = new HashMap<>();

  static {
    for (final CiphertextType s : EnumSet.allOf(CiphertextType.class)) {
      ID_MAPPING.put(s.value_, s);
    }
  }

  private CiphertextType(final int value) {
    /*
     * Java reads literals as integers. So we cast the integer value to byte
     * here to avoid doing this in the enum definitions above.
     */
    value_ = (byte) value;
  }

  /**
   * Return the value used to encode this ciphertext type object in the ciphertext.
   *
   * @return the byte value used to encode this ciphertext type.
   */
  public byte getValue() {
    return value_;
  }

  /**
   * Deserialize the provided byte value by returning the CiphertextType object representing the
   * byte value.
   *
   * @param value the byte representing the value of the CiphertextType object.
   * @return the CiphertextType object representing the byte value.
   */
  public static CiphertextType deserialize(final byte value) {
    final Byte valueByte = Byte.valueOf(value);
    final CiphertextType result = ID_MAPPING.get(valueByte);
    return result;
  }
}
