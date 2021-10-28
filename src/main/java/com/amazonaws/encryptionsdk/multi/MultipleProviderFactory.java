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

package com.amazonaws.encryptionsdk.multi;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.MasterKeyRequest;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.internal.Utils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Constructs {@link MasterKeyProvider}s which are backed by any number of other {@link
 * MasterKeyProvider}s. The returned provider will have the following properties:
 *
 * <ul>
 *   <li>{@link MasterKeyProvider#getMasterKeysForEncryption(MasterKeyRequest)} will result in the
 *       union of all responses from the backing providers. Likewise,
 *   <li>{@link MasterKeyProvider#decryptDataKey(CryptoAlgorithm, Collection, Map)} will succeed if
 *       and only if at least one backing provider can successfully decrypt the {@link DataKey}s.
 *   <li>{@link MasterKeyProvider#getDefaultProviderId()} is delegated to the first backing
 *       provider.
 *   <li>{@link MasterKeyProvider#getMasterKey(String, String)} will attempt to find the appropriate
 *       backing provider to return a {@link MasterKey}.
 * </ul>
 *
 * All methods in this factory return identical results and exist only for different degrees of
 * type-safety.
 */
public class MultipleProviderFactory {
  private MultipleProviderFactory() {
    // Prevent instantiation
  }

  public static <K extends MasterKey<K>> MasterKeyProvider<K> buildMultiProvider(
      final Class<K> masterKeyClass,
      final List<? extends MasterKeyProvider<? extends K>> providers) {
    return new MultiProvider<K>(providers);
  }

  @SafeVarargs
  public static <K extends MasterKey<K>, P extends MasterKeyProvider<? extends K>>
      MasterKeyProvider<K> buildMultiProvider(final Class<K> masterKeyClass, final P... providers) {
    return buildMultiProvider(masterKeyClass, Arrays.asList(providers));
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  public static MasterKeyProvider<?> buildMultiProvider(
      final List<? extends MasterKeyProvider<?>> providers) {
    return new MultiProvider(providers);
  }

  @SafeVarargs
  public static <P extends MasterKeyProvider<?>> MasterKeyProvider<?> buildMultiProvider(
      final P... providers) {
    return buildMultiProvider(Arrays.asList(providers));
  }

  private static class MultiProvider<K extends MasterKey<K>> extends MasterKeyProvider<K> {
    private final List<? extends MasterKeyProvider<? extends K>> providers_;

    private MultiProvider(final List<? extends MasterKeyProvider<? extends K>> providers) {
      Utils.assertNonNull(providers, "providers");
      if (providers.isEmpty()) {
        throw new IllegalArgumentException("providers must not be empty");
      }
      providers_ = new ArrayList<>(providers);
    }

    @Override
    public String getDefaultProviderId() {
      return providers_.get(0).getDefaultProviderId();
    }

    @Override
    public K getMasterKey(final String keyId)
        throws UnsupportedProviderException, NoSuchMasterKeyException {
      for (final MasterKeyProvider<? extends K> prov : providers_) {
        try {
          final K result = prov.getMasterKey(keyId);
          if (result != null) {
            return result;
          }
        } catch (final NoSuchMasterKeyException ex) {
          // swallow and continue
        }
      }
      throw new NoSuchMasterKeyException();
    }

    @Override
    public K getMasterKey(final String provider, final String keyId)
        throws UnsupportedProviderException, NoSuchMasterKeyException {
      boolean foundProvider = false;
      for (final MasterKeyProvider<? extends K> prov : providers_) {
        if (prov.canProvide(provider)) {
          foundProvider = true;
          try {
            final K result = prov.getMasterKey(provider, keyId);
            if (result != null) {
              return result;
            }
          } catch (final NoSuchMasterKeyException ex) {
            // swallow and continue
          }
        }
      }
      if (foundProvider) {
        throw new NoSuchMasterKeyException();
      } else {
        throw new UnsupportedProviderException(provider);
      }
    }

    @Override
    public List<K> getMasterKeysForEncryption(final MasterKeyRequest request) {
      final List<K> result = new ArrayList<>();
      for (final MasterKeyProvider<? extends K> prov : providers_) {
        result.addAll(prov.getMasterKeysForEncryption(request));
      }
      return result;
    }

    @SuppressWarnings("unchecked")
    @Override
    public DataKey<K> decryptDataKey(
        final CryptoAlgorithm algorithm,
        final Collection<? extends EncryptedDataKey> encryptedDataKeys,
        final Map<String, String> encryptionContext)
        throws UnsupportedProviderException, AwsCryptoException {
      final List<Exception> exceptions = new ArrayList<>();
      for (final MasterKeyProvider<? extends K> prov : providers_) {
        try {
          final DataKey<? extends K> result =
              prov.decryptDataKey(algorithm, encryptedDataKeys, encryptionContext);
          if (result != null) {
            return (DataKey<K>) result;
          }
        } catch (final Exception ex) {
          exceptions.add(ex);
        }
      }
      throw buildCannotDecryptDksException(exceptions);
    }
  }
}
