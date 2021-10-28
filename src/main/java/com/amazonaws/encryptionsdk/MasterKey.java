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

import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Represents the cryptographic key used to protect the {@link DataKey} (which, in turn, protects
 * the data).
 *
 * <p>All MasterKeys extend {@link MasterKeyProvider} because they are all capable of providing
 * exactly themselves. This simplifies implementation when only a single {@link MasterKey} is used
 * and/or expected.
 *
 * @param <K> the concrete type of the {@link MasterKey}
 */
public abstract class MasterKey<K extends MasterKey<K>> extends MasterKeyProvider<K> {
  public abstract String getProviderId();

  /** Equivalent to calling {@link #getProviderId()}. */
  @Override
  public String getDefaultProviderId() {
    return getProviderId();
  }

  public abstract String getKeyId();

  /**
   * Generates a new {@link DataKey} which is protected by this {@link MasterKey} for use with
   * {@code algorithm} and associated with the provided {@code encryptionContext}.
   */
  public abstract DataKey<K> generateDataKey(
      CryptoAlgorithm algorithm, Map<String, String> encryptionContext);

  /**
   * Returns a new copy of the provided {@code dataKey} which is protected by this {@link MasterKey}
   * for use with {@code algorithm} and associated with the provided {@code encryptionContext}.
   */
  public abstract DataKey<K> encryptDataKey(
      CryptoAlgorithm algorithm, Map<String, String> encryptionContext, DataKey<?> dataKey);

  /** Returns {@code true} if and only if {@code provider} equals {@link #getProviderId()}. */
  @Override
  public boolean canProvide(final String provider) {
    return getProviderId().equals(provider);
  }

  /**
   * Returns {@code this} if {@code provider} and {@code keyId} match {@code this}. Otherwise,
   * throws an appropriate exception.
   */
  @SuppressWarnings("unchecked")
  @Override
  public K getMasterKey(final String provider, final String keyId)
      throws UnsupportedProviderException, NoSuchMasterKeyException {
    if (!canProvide(provider)) {
      throw new UnsupportedProviderException(
          "MasterKeys can only provide themselves. Requested "
              + buildName(provider, keyId)
              + " but only "
              + toString()
              + " is available");
    }
    if (!getKeyId().equals(keyId)) {
      throw new NoSuchMasterKeyException(
          "MasterKeys can only provide themselves. Requested "
              + buildName(provider, keyId)
              + " but only "
              + toString()
              + " is available");
    }
    return (K) this;
  }

  @Override
  public String toString() {
    return buildName(getProviderId(), getKeyId());
  }

  /** Returns a list of length {@code 1} containing {@code this}. */
  @SuppressWarnings("unchecked")
  @Override
  public List<K> getMasterKeysForEncryption(final MasterKeyRequest request) {
    return (List<K>) Collections.singletonList(this);
  }

  private static String buildName(final String provider, final String keyId) {
    return String.format("%s://%s", provider, keyId);
  }

  /**
   * Two {@link MasterKey}s are equal if they are instances of the <em>exact same class</em> and
   * their values for {@code keyId}, {@code providerId}, and {@code defaultProviderId} are equal.
   */
  @Override
  public boolean equals(final Object obj) {
    if (obj == null) {
      return false;
    }
    if (this == obj) {
      return true;
    }
    if (!obj.getClass().equals(getClass())) {
      return false;
    }
    final MasterKey<?> mk = (MasterKey<?>) obj;
    return Objects.equals(getKeyId(), mk.getKeyId())
        && Objects.equals(getProviderId(), mk.getProviderId())
        && Objects.equals(getDefaultProviderId(), mk.getDefaultProviderId());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getKeyId(), getProviderId(), getDefaultProviderId());
  }
}
