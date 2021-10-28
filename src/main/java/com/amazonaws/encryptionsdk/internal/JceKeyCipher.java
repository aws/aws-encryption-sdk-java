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

import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.apache.commons.lang3.ArrayUtils;

/** Abstract class for encrypting and decrypting JCE data keys. */
public abstract class JceKeyCipher {

  private final Key wrappingKey;
  private final Key unwrappingKey;
  private static final Charset KEY_NAME_ENCODING = StandardCharsets.UTF_8;

  /**
   * Returns a new instance of a JceKeyCipher based on the Advanced Encryption Standard in
   * Galois/Counter Mode.
   *
   * @param secretKey The secret key to use for encrypt/decrypt operations.
   * @return The JceKeyCipher.
   */
  public static JceKeyCipher aesGcm(SecretKey secretKey) {
    return new AesGcmJceKeyCipher(secretKey);
  }

  /**
   * Returns a new instance of a JceKeyCipher based on RSA.
   *
   * @param wrappingKey The public key to use for encrypting the key.
   * @param unwrappingKey The private key to use for decrypting the key.
   * @param transformation The transformation.
   * @return The JceKeyCipher.
   */
  public static JceKeyCipher rsa(
      PublicKey wrappingKey, PrivateKey unwrappingKey, String transformation) {
    return new RsaJceKeyCipher(wrappingKey, unwrappingKey, transformation);
  }

  JceKeyCipher(Key wrappingKey, Key unwrappingKey) {
    this.wrappingKey = wrappingKey;
    this.unwrappingKey = unwrappingKey;
  }

  abstract WrappingData buildWrappingCipher(Key key, Map<String, String> encryptionContext)
      throws GeneralSecurityException;

  abstract Cipher buildUnwrappingCipher(
      Key key, byte[] extraInfo, int offset, Map<String, String> encryptionContext)
      throws GeneralSecurityException;

  /**
   * Encrypts the given key, incorporating the given keyName and encryptionContext.
   *
   * @param key The key to encrypt.
   * @param keyName A UTF-8 encoded representing a name for the key.
   * @param keyNamespace A UTF-8 encoded value that namespaces the key.
   * @param encryptionContext A key-value mapping of arbitrary, non-secret, UTF-8 encoded strings
   *     used during encryption and decryption to provide additional authenticated data (AAD).
   * @return The encrypted data key.
   */
  public EncryptedDataKey encryptKey(
      final byte[] key,
      final String keyName,
      final String keyNamespace,
      final Map<String, String> encryptionContext) {

    final byte[] keyNameBytes = keyName.getBytes(KEY_NAME_ENCODING);

    try {
      final JceKeyCipher.WrappingData wData = buildWrappingCipher(wrappingKey, encryptionContext);
      final Cipher cipher = wData.cipher;
      final byte[] encryptedKey = cipher.doFinal(key);

      final byte[] provInfo;
      if (wData.extraInfo.length == 0) {
        provInfo = keyNameBytes;
      } else {
        provInfo = new byte[keyNameBytes.length + wData.extraInfo.length];
        System.arraycopy(keyNameBytes, 0, provInfo, 0, keyNameBytes.length);
        System.arraycopy(wData.extraInfo, 0, provInfo, keyNameBytes.length, wData.extraInfo.length);
      }

      return new KeyBlob(keyNamespace, provInfo, encryptedKey);
    } catch (final GeneralSecurityException gsex) {
      throw new AwsCryptoException(gsex);
    }
  }

  /**
   * Decrypts the given encrypted data key.
   *
   * @param edk The encrypted data key.
   * @param keyName A UTF-8 encoded String representing a name for the key.
   * @param encryptionContext A key-value mapping of arbitrary, non-secret, UTF-8 encoded strings
   *     used during encryption and decryption to provide additional authenticated data (AAD).
   * @return The decrypted key.
   * @throws GeneralSecurityException If a problem occurred decrypting the key.
   */
  public byte[] decryptKey(
      final EncryptedDataKey edk, final String keyName, final Map<String, String> encryptionContext)
      throws GeneralSecurityException {
    final byte[] keyNameBytes = keyName.getBytes(KEY_NAME_ENCODING);

    final Cipher cipher =
        buildUnwrappingCipher(
            unwrappingKey, edk.getProviderInformation(), keyNameBytes.length, encryptionContext);
    return cipher.doFinal(edk.getEncryptedDataKey());
  }

  static class WrappingData {
    public final Cipher cipher;
    public final byte[] extraInfo;

    WrappingData(final Cipher cipher, final byte[] extraInfo) {
      this.cipher = cipher;
      this.extraInfo = extraInfo != null ? extraInfo : ArrayUtils.EMPTY_BYTE_ARRAY;
    }
  }
}
