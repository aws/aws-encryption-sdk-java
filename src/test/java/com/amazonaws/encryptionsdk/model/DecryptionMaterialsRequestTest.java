/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.model;

import static org.junit.Assert.assertEquals;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class DecryptionMaterialsRequestTest {
  @Test
  public void build() {
    CryptoAlgorithm alg = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("DMR", "DecryptionMaterialsRequest Test");
    List<KeyBlob> kbs = new ArrayList<KeyBlob>();

    DecryptionMaterialsRequest request0 =
        DecryptionMaterialsRequest.newBuilder()
            .setAlgorithm(alg)
            .setEncryptionContext(encryptionContext)
            .setEncryptedDataKeys(kbs)
            .build();

    DecryptionMaterialsRequest request1 = request0.toBuilder().build();

    assertEquals(request0.getAlgorithm(), request1.getAlgorithm());
    assertEquals(request0.getEncryptionContext().size(), request1.getEncryptionContext().size());
    assertEquals(request0.getEncryptedDataKeys().size(), request1.getEncryptedDataKeys().size());
  }
}
