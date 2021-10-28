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

package com.amazonaws.encryptionsdk.internal;

import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import java.util.List;
import java.util.Map;

public interface MessageCryptoHandler extends CryptoHandler {
  /**
   * Informs this handler of an upper bound on the input data size. The handler will throw an
   * exception if this bound is exceeded, and may use it to perform performance optimizations as
   * well.
   *
   * <p>If this method is called multiple times, the smallest bound will be used.
   *
   * @param size An upper bound on the input data size.
   */
  void setMaxInputLength(long size);

  /**
   * Return the encryption context used in the generation of the data key used for the encryption of
   * content.
   *
   * <p>During decryption, this value should be obtained by parsing the ciphertext headers that
   * encodes this value.
   *
   * @return the key-value map containing the encryption context.
   */
  Map<String, String> getEncryptionContext();

  CiphertextHeaders getHeaders();

  /**
   * All <em>used</em> {@link MasterKey}s. For encryption flows, these are all the {@link
   * MasterKey}s used to protect the data. In the decryption flow, it is the single {@link
   * MasterKey} actually used to decrypt the data.
   */
  List<? extends MasterKey<?>> getMasterKeys();
}
