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

package com.amazonaws.encryptionsdk.internal;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** A JceKeyCipher based on the Advanced Encryption Standard in Galois/Counter Mode. */
class AesGcmJceKeyCipher extends JceKeyCipher {
  private static final int NONCE_LENGTH = 12;
  private static final int TAG_LENGTH = 128;
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int SPEC_LENGTH = Integer.BYTES + Integer.BYTES + NONCE_LENGTH;

  AesGcmJceKeyCipher(SecretKey key) {
    super(key, key);
  }

  private static byte[] specToBytes(final GCMParameterSpec spec) {
    final byte[] nonce = spec.getIV();
    final byte[] result = new byte[SPEC_LENGTH];
    final ByteBuffer buffer = ByteBuffer.wrap(result);
    buffer.putInt(spec.getTLen());
    buffer.putInt(nonce.length);
    buffer.put(nonce);
    return result;
  }

  private static GCMParameterSpec bytesToSpec(final byte[] data, final int offset)
      throws InvalidKeyException {
    if (data.length - offset != SPEC_LENGTH) {
      throw new InvalidKeyException("Algorithm specification was an invalid data size");
    }

    final ByteBuffer buffer = ByteBuffer.wrap(data, offset, SPEC_LENGTH);
    final int tagLen = buffer.getInt();
    final int nonceLen = buffer.getInt();

    if (tagLen != TAG_LENGTH) {
      throw new InvalidKeyException(
          String.format("Authentication tag length must be %s", TAG_LENGTH));
    }

    if (nonceLen != NONCE_LENGTH) {
      throw new InvalidKeyException(
          String.format("Initialization vector (IV) length must be %s", NONCE_LENGTH));
    }

    final byte[] nonce = new byte[nonceLen];
    buffer.get(nonce);

    return new GCMParameterSpec(tagLen, nonce);
  }

  @Override
  WrappingData buildWrappingCipher(final Key key, final Map<String, String> encryptionContext)
      throws GeneralSecurityException {
    final byte[] nonce = new byte[NONCE_LENGTH];
    Utils.getSecureRandom().nextBytes(nonce);
    final GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, nonce);
    final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    final byte[] aad = EncryptionContextSerializer.serialize(encryptionContext);
    cipher.updateAAD(aad);
    return new WrappingData(cipher, specToBytes(spec));
  }

  @Override
  Cipher buildUnwrappingCipher(
      final Key key,
      final byte[] extraInfo,
      final int offset,
      final Map<String, String> encryptionContext)
      throws GeneralSecurityException {
    final GCMParameterSpec spec = bytesToSpec(extraInfo, offset);
    final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, key, spec);
    final byte[] aad = EncryptionContextSerializer.serialize(encryptionContext);
    cipher.updateAAD(aad);
    return cipher;
  }
}
