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

import javax.crypto.SecretKey;

/**
 * Represents both the cleartext and encrypted bytes of a data key.
 *
 * @param <M> the type of {@link MasterKey} used to protect this {@code DataKey}.
 */
public class DataKey<M extends MasterKey<M>> implements EncryptedDataKey {
  private final byte[] providerInformation_;
  private final byte[] encryptedDataKey_;
  private final SecretKey key_;
  private final M masterKey_;

  public DataKey(
      final SecretKey key,
      final byte[] encryptedDataKey,
      final byte[] providerInformation,
      final M masterKey) {
    super();
    key_ = key;
    encryptedDataKey_ = encryptedDataKey.clone();
    providerInformation_ = providerInformation.clone();
    masterKey_ = masterKey;
  }

  /** Returns the cleartext bytes of the data key. */
  public SecretKey getKey() {
    return key_;
  }

  @Override
  public String getProviderId() {
    return masterKey_.getProviderId();
  }

  @Override
  public byte[] getProviderInformation() {
    return providerInformation_.clone();
  }

  @Override
  public byte[] getEncryptedDataKey() {
    return encryptedDataKey_.clone();
  }

  /** Returns the {@link MasterKey} used to encrypt this {@link DataKey}. */
  public M getMasterKey() {
    return masterKey_;
  }
}
