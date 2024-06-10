// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.model;

import org.junit.Test;

import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

public class DecryptionMaterialsTest {

  @Test
  public void GIVEN_builder_with_null_EC_WHEN_constructor_THEN_object_EC_is_empty_map() {
    // Given: null encryption context
    DecryptionMaterials.Builder builder = DecryptionMaterials.newBuilder();

    // When: constructor
    DecryptionMaterials decryptionMaterials = builder.build();

    // Then: constructor assigns an empty map to DecryptionMaterials objects
    assertEquals(Collections.emptyMap(), decryptionMaterials.getEncryptionContext());
  }

  @Test
  public void GIVEN_builder_with_EC_WHEN_constructor_THEN_object_EC_is_builder_EC() {
    // Given: any non-null encryption context map
    Map<String, String> mockEncryptionContext = mock(Map.class);
    DecryptionMaterials.Builder builder = DecryptionMaterials.newBuilder();
    builder.setEncryptionContext(mockEncryptionContext);

    // When: constructor
    DecryptionMaterials decryptionMaterials = builder.build();

    // Then: constructor assigns that encryption context map to DecryptionMaterials objects
    assertEquals(mockEncryptionContext, decryptionMaterials.getEncryptionContext());
  }
}
