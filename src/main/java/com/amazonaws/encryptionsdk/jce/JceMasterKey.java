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

package com.amazonaws.encryptionsdk.jce;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.internal.JceKeyCipher;
import com.amazonaws.encryptionsdk.internal.Utils;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Represents a {@link MasterKey} backed by one (or more) JCE {@link Key}s. Instances of this should
 * only be acquired using {@link #getInstance(SecretKey, String, String, String)} or {@link
 * #getInstance(PublicKey, PrivateKey, String, String, String)}.
 */
public class JceMasterKey extends MasterKey<JceMasterKey> {
  private final String providerName_;
  private final String keyId_;
  private final byte[] keyIdBytes_;
  private final JceKeyCipher jceKeyCipher_;

  /**
   * Returns a {@code JceMasterKey} backed by the symmetric key {@code key} using {@code
   * wrappingAlgorithm}. Currently "{@code AES/GCM/NoPadding}" is the only supported value for
   * symmetric {@code wrappingAlgorithm}s.
   *
   * @param key key used to wrap/unwrap (encrypt/decrypt) {@link DataKey}s
   * @param provider
   * @param keyId
   * @param wrappingAlgorithm
   * @return
   */
  public static JceMasterKey getInstance(
      final SecretKey key,
      final String provider,
      final String keyId,
      final String wrappingAlgorithm) {
    switch (wrappingAlgorithm.toUpperCase()) {
      case "AES/GCM/NOPADDING":
        return new JceMasterKey(provider, keyId, JceKeyCipher.aesGcm(key));
      default:
        throw new IllegalArgumentException("Right now only AES/GCM/NoPadding is supported");
    }
  }

  /**
   * Returns a {@code JceMasterKey} backed by the asymmetric key pair {@code unwrappingKey} and
   * {@code wrappingKey} using {@code wrappingAlgorithm}. Currently only RSA algorithms are
   * supported for asymmetric {@code wrappingAlgorithm}s. If {@code unwrappingKey} is {@code null}
   * then the returned {@link JceMasterKey} can only be used for encryption.
   *
   * @param wrappingKey key used to wrap (encrypt) {@link DataKey}s
   * @param unwrappingKey (Optional) key used to unwrap (decrypt) {@link DataKey}s.
   */
  public static JceMasterKey getInstance(
      final PublicKey wrappingKey,
      final PrivateKey unwrappingKey,
      final String provider,
      final String keyId,
      final String wrappingAlgorithm) {
    if (wrappingAlgorithm.toUpperCase().startsWith("RSA/ECB/")) {
      return new JceMasterKey(
          provider, keyId, JceKeyCipher.rsa(wrappingKey, unwrappingKey, wrappingAlgorithm));
    }
    throw new UnsupportedOperationException(
        "Currently only RSA asymmetric algorithms are supported");
  }

  protected JceMasterKey(
      final String providerName, final String keyId, final JceKeyCipher jceKeyCipher) {
    providerName_ = providerName;
    keyId_ = keyId;
    keyIdBytes_ = keyId_.getBytes(StandardCharsets.UTF_8);
    jceKeyCipher_ = jceKeyCipher;
  }

  @Override
  public String getProviderId() {
    return providerName_;
  }

  @Override
  public String getKeyId() {
    return keyId_;
  }

  @Override
  public DataKey<JceMasterKey> generateDataKey(
      final CryptoAlgorithm algorithm, final Map<String, String> encryptionContext) {
    final byte[] rawKey = new byte[algorithm.getDataKeyLength()];
    Utils.getSecureRandom().nextBytes(rawKey);
    EncryptedDataKey encryptedDataKey =
        jceKeyCipher_.encryptKey(rawKey, keyId_, providerName_, encryptionContext);
    return new DataKey<>(
        new SecretKeySpec(rawKey, algorithm.getDataKeyAlgo()),
        encryptedDataKey.getEncryptedDataKey(),
        encryptedDataKey.getProviderInformation(),
        this);
  }

  @Override
  public DataKey<JceMasterKey> encryptDataKey(
      final CryptoAlgorithm algorithm,
      final Map<String, String> encryptionContext,
      final DataKey<?> dataKey) {
    final SecretKey key = dataKey.getKey();
    if (!key.getFormat().equals("RAW")) {
      throw new IllegalArgumentException(
          "Can only re-encrypt data keys which are in RAW format, not "
              + dataKey.getKey().getFormat());
    }
    if (!key.getAlgorithm().equalsIgnoreCase(algorithm.getDataKeyAlgo())) {
      throw new IllegalArgumentException(
          "Incorrect key algorithm. Expected "
              + key.getAlgorithm()
              + " but got "
              + algorithm.getKeyAlgo());
    }
    EncryptedDataKey encryptedDataKey =
        jceKeyCipher_.encryptKey(key.getEncoded(), keyId_, providerName_, encryptionContext);
    return new DataKey<>(
        key,
        encryptedDataKey.getEncryptedDataKey(),
        encryptedDataKey.getProviderInformation(),
        this);
  }

  @Override
  public DataKey<JceMasterKey> decryptDataKey(
      final CryptoAlgorithm algorithm,
      final Collection<? extends EncryptedDataKey> encryptedDataKeys,
      final Map<String, String> encryptionContext)
      throws UnsupportedProviderException, AwsCryptoException {
    final List<Exception> exceptions = new ArrayList<>();
    // Find an encrypted key who's provider and info match us
    for (final EncryptedDataKey edk : encryptedDataKeys) {
      try {
        if (edk.getProviderId().equals(getProviderId())
            && Utils.arrayPrefixEquals(
                edk.getProviderInformation(), keyIdBytes_, keyIdBytes_.length)) {
          final byte[] decryptedKey = jceKeyCipher_.decryptKey(edk, keyId_, encryptionContext);

          // Validate that the decrypted key length is as expected
          if (decryptedKey.length == algorithm.getDataKeyLength()) {
            return new DataKey<>(
                new SecretKeySpec(decryptedKey, algorithm.getDataKeyAlgo()),
                edk.getEncryptedDataKey(),
                edk.getProviderInformation(),
                this);
          }
        }
      } catch (final Exception ex) {
        exceptions.add(ex);
      }
    }
    throw buildCannotDecryptDksException(exceptions);
  }
}
