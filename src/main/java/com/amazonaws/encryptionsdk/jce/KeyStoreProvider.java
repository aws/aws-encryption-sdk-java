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
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.MasterKeyRequest;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * This {@link MasterKeyProvider} provides keys backed by a JCE {@link KeyStore}. Please see {@link
 * #decryptDataKey(CryptoAlgorithm, Collection, Map)} for an of how decryption is managed and see
 * {@link #getMasterKeysForEncryption(MasterKeyRequest)} for an explanation of how encryption is
 * managed.
 */
public class KeyStoreProvider extends MasterKeyProvider<JceMasterKey> {
  private final String providerName_;
  private final KeyStore keystore_;
  private final ProtectionParameter protection_;
  private final String wrappingAlgorithm_;
  private final String keyAlgorithm_;
  private final List<String> aliasNames_;

  /**
   * Creates an instance of this class using {@code wrappingAlgorithm} which will work <em>for
   * decrypt only</em>.
   */
  public KeyStoreProvider(
      final KeyStore keystore,
      final ProtectionParameter protection,
      final String providerName,
      final String wrappingAlgorithm) {
    this(keystore, protection, providerName, wrappingAlgorithm, new String[0]);
  }

  /**
   * Creates an instance of this class using {@code wrappingAlgorithm} which will encrypt data to
   * the keys specified by {@code aliasNames}.
   */
  public KeyStoreProvider(
      final KeyStore keystore,
      final ProtectionParameter protection,
      final String providerName,
      final String wrappingAlgorithm,
      final String... aliasNames) {
    keystore_ = keystore;
    protection_ = protection;
    wrappingAlgorithm_ = wrappingAlgorithm;
    aliasNames_ = Arrays.asList(aliasNames);
    providerName_ = providerName;
    keyAlgorithm_ = wrappingAlgorithm.split("/", 2)[0].toUpperCase();
  }

  /**
   * Returns a {@link JceMasterKey} corresponding to the entry in the {@link KeyStore} with the
   * specified alias and compatible algorithm.
   */
  @Override
  public JceMasterKey getMasterKey(final String provider, final String keyId)
      throws UnsupportedProviderException, NoSuchMasterKeyException {
    if (!canProvide(provider)) {
      throw new UnsupportedProviderException();
    }
    final JceMasterKey result = internalGetMasterKey(provider, keyId);
    if (result == null) {
      throw new NoSuchMasterKeyException();
    } else {
      return result;
    }
  }

  private JceMasterKey internalGetMasterKey(final String provider, final String keyId) {
    final Entry entry;
    try {
      entry = keystore_.getEntry(keyId, keystore_.isKeyEntry(keyId) ? protection_ : null);
    } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
      throw new UnsupportedProviderException(e);
    }
    if (entry == null) {
      throw new NoSuchMasterKeyException();
    }
    if (entry instanceof SecretKeyEntry) {
      final SecretKeyEntry skEntry = (SecretKeyEntry) entry;
      if (!skEntry.getSecretKey().getAlgorithm().equals(keyAlgorithm_)) {
        return null;
      }
      return JceMasterKey.getInstance(skEntry.getSecretKey(), provider, keyId, wrappingAlgorithm_);
    } else if (entry instanceof PrivateKeyEntry) {
      final PrivateKeyEntry pkEntry = (PrivateKeyEntry) entry;
      if (!pkEntry.getPrivateKey().getAlgorithm().equals(keyAlgorithm_)) {
        return null;
      }
      return JceMasterKey.getInstance(
          pkEntry.getCertificate().getPublicKey(),
          pkEntry.getPrivateKey(),
          provider,
          keyId,
          wrappingAlgorithm_);
    } else if (entry instanceof TrustedCertificateEntry) {
      final TrustedCertificateEntry certEntry = (TrustedCertificateEntry) entry;
      if (!certEntry.getTrustedCertificate().getPublicKey().getAlgorithm().equals(keyAlgorithm_)) {
        return null;
      }
      return JceMasterKey.getInstance(
          certEntry.getTrustedCertificate().getPublicKey(),
          null,
          provider,
          keyId,
          wrappingAlgorithm_);
    } else {
      throw new NoSuchMasterKeyException();
    }
  }

  /** Returns "JavaKeyStore". */
  @Override
  public String getDefaultProviderId() {
    return providerName_;
  }

  /**
   * Returns {@link JceMasterKey}s corresponding to the {@code aliasNames} passed into the
   * constructor.
   */
  @Override
  public List<JceMasterKey> getMasterKeysForEncryption(final MasterKeyRequest request) {
    if (aliasNames_ != null) {
      final List<JceMasterKey> result = new ArrayList<>();
      for (final String alias : aliasNames_) {
        result.add(getMasterKey(alias));
      }
      return result;
    } else {
      return Collections.emptyList();
    }
  }

  /**
   * Attempts to decrypts the {@code encryptedDataKeys} by first iterating through all {@code
   * aliasNames} specified in the constructor and then over <em>all other compatible keys</em> in
   * the {@link KeyStore}. This includes {@code TrustedCertificates} as well as standard key
   * entries.
   */
  @Override
  public DataKey<JceMasterKey> decryptDataKey(
      final CryptoAlgorithm algorithm,
      final Collection<? extends EncryptedDataKey> encryptedDataKeys,
      final Map<String, String> encryptionContext)
      throws UnsupportedProviderException, AwsCryptoException {
    final List<Exception> exceptions = new ArrayList<>();
    for (final EncryptedDataKey edk : encryptedDataKeys) {
      try {
        if (canProvide(edk.getProviderId())) {
          final String alias = new String(edk.getProviderInformation(), StandardCharsets.UTF_8);
          if (keystore_.isKeyEntry(alias)) {
            final DataKey<JceMasterKey> result =
                getMasterKey(alias)
                    .decryptDataKey(algorithm, Collections.singletonList(edk), encryptionContext);
            if (result != null) {
              return result;
            }
          }
        }
      } catch (final Exception ex) {
        exceptions.add(ex);
      }
    }

    throw buildCannotDecryptDksException(exceptions);
  }
}
