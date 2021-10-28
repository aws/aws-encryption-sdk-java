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

import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Represents the result of an operation by {@link AwsCrypto}. It not only captures the {@code
 * result} of the operation but also additional metadata such as the {@code encryptionContext},
 * {@code algorithm}, {@link MasterKey}(s), and any other information captured in the {@link
 * CiphertextHeaders}.
 *
 * @param <T> the type of the underlying {@code result}
 * @param <K> the type of the {@link MasterKey}s used in production of this result
 */
public class CryptoResult<T, K extends MasterKey<K>> {
  private final T result_;
  private final List<K> masterKeys_;
  private final Map<String, String> encryptionContext_;
  private final CiphertextHeaders headers_;

  /** Note, does not make a defensive copy of any of the data. */
  CryptoResult(final T result, final List<K> masterKeys, final CiphertextHeaders headers) {
    result_ = result;
    masterKeys_ = Collections.unmodifiableList(masterKeys);
    headers_ = headers;
    encryptionContext_ = headers_.getEncryptionContextMap();
  }

  /**
   * The actual result of the cryptographic operation. This is not a defensive copy and callers
   * should not modify it.
   *
   * @return
   */
  public T getResult() {
    return result_;
  }

  /**
   * Returns all relevant {@link MasterKey}s. In the case of encryption, returns all {@code
   * MasterKey}s used to protect the ciphertext. In the case of decryption, returns just the {@code
   * MasterKey} used to decrypt the ciphertext.
   *
   * @return
   */
  public List<K> getMasterKeys() {
    return masterKeys_;
  }

  /** Convenience method for retrieving the keyIds in the results from {@link #getMasterKeys()}. */
  public List<String> getMasterKeyIds() {
    final List<String> result = new ArrayList<>(masterKeys_.size());
    for (final MasterKey<K> mk : masterKeys_) {
      result.add(mk.getKeyId());
    }
    return result;
  }

  public Map<String, String> getEncryptionContext() {
    return encryptionContext_;
  }

  /** Convenience method equivalent to {@link #getHeaders()}.{@code getCryptoAlgoId()}. */
  public CryptoAlgorithm getCryptoAlgorithm() {
    return headers_.getCryptoAlgoId();
  }

  public CiphertextHeaders getHeaders() {
    return headers_;
  }
}
