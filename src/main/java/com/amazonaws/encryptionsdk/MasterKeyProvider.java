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

package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Represents the logic necessary to select and construct {@link MasterKey}s for encrypting and
 * decrypting messages. This is an abstract class.
 *
 * @param <K> the type of {@link MasterKey} returned by this provider
 */
public abstract class MasterKeyProvider<K extends MasterKey<K>> {
  /** ProviderId used by this instance when no other is specified. */
  public abstract String getDefaultProviderId();

  /**
   * Returns true if this MasterKeyProvider can provide keys from the specified @{code provider}.
   *
   * @param provider
   * @return
   */
  public boolean canProvide(final String provider) {
    return getDefaultProviderId().equals(provider);
  }

  /**
   * Equivalent to calling {@link #getMasterKey(String, String)} using {@link
   * #getDefaultProviderId()} as the provider.
   */
  public K getMasterKey(final String keyId)
      throws UnsupportedProviderException, NoSuchMasterKeyException {
    return getMasterKey(getDefaultProviderId(), keyId);
  }

  /**
   * Returns the specified {@link MasterKey} if possible.
   *
   * @param provider
   * @param keyId
   * @return
   * @throws UnsupportedProviderException if this object cannot return {@link MasterKey}s associated
   *     with the given provider
   * @throws NoSuchMasterKeyException if this object cannot find (and thus construct) the {@link
   *     MasterKey} associated with {@code keyId}
   */
  public abstract K getMasterKey(String provider, String keyId)
      throws UnsupportedProviderException, NoSuchMasterKeyException;

  /**
   * Returns all {@link MasterKey}s which should be used to protect the plaintext described by
   * {@code request}.
   */
  public abstract List<K> getMasterKeysForEncryption(MasterKeyRequest request);

  /**
   * Iterates through {@code encryptedDataKeys} and returns the first one which can be successfully
   * decrypted.
   *
   * @return a DataKey if one can be decrypted, otherwise returns {@code null}
   * @throws UnsupportedProviderException if the {@code encryptedDataKey} is associated with an
   *     unsupported provider
   * @throws CannotUnwrapDataKeyException if the {@code encryptedDataKey} cannot be decrypted
   */
  public abstract DataKey<K> decryptDataKey(
      CryptoAlgorithm algorithm,
      Collection<? extends EncryptedDataKey> encryptedDataKeys,
      Map<String, String> encryptionContext)
      throws UnsupportedProviderException, AwsCryptoException;

  protected AwsCryptoException buildCannotDecryptDksException() {
    return buildCannotDecryptDksException(Collections.<Throwable>emptyList());
  }

  protected AwsCryptoException buildCannotDecryptDksException(Throwable t) {
    return buildCannotDecryptDksException(Collections.singletonList(t));
  }

  protected AwsCryptoException buildCannotDecryptDksException(List<? extends Throwable> t) {
    if (t == null || t.isEmpty()) {
      return new CannotUnwrapDataKeyException("Unable to decrypt any data keys");
    } else {
      final CannotUnwrapDataKeyException ex =
          new CannotUnwrapDataKeyException("Unable to decrypt any data keys", t.get(0));
      for (final Throwable e : t) {
        ex.addSuppressed(e);
      }
      return ex;
    }
  }
}
