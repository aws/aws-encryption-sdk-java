// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsHandler;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class CMMHandlerTest {

  private static final CryptoAlgorithm SOME_CRYPTO_ALGORITHM =
      CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
  private static final List<KeyBlob> SOME_EDK_LIST =
      new ArrayList<>(Collections.singletonList(new KeyBlob()));
  private static final CommitmentPolicy SOME_COMMITMENT_POLICY =
      CommitmentPolicy.RequireEncryptRequireDecrypt;
  private static final Map<String, String> SOME_NON_EMPTY_ENCRYPTION_CONTEXT = new HashMap<>();

  static {
    {
      SOME_NON_EMPTY_ENCRYPTION_CONTEXT.put("SomeKey", "SomeValue");
    }
  }

  private static final DecryptionMaterialsRequest SOME_DECRYPTION_MATERIALS_REQUEST_NON_EMPTY_EC =
      DecryptionMaterialsRequest.newBuilder()
          .setAlgorithm(SOME_CRYPTO_ALGORITHM)
          // Given: Request has some non-empty encryption context
          .setEncryptionContext(SOME_NON_EMPTY_ENCRYPTION_CONTEXT)
          .setReproducedEncryptionContext(new HashMap<>())
          .setEncryptedDataKeys(SOME_EDK_LIST)
          .build();

  private static final DecryptionMaterialsRequest SOME_DECRYPTION_MATERIALS_REQUEST_EMPTY_EC =
      DecryptionMaterialsRequest.newBuilder()
          .setAlgorithm(SOME_CRYPTO_ALGORITHM)
          // Given: Request has empty encryption context
          .setEncryptionContext(new HashMap<>())
          .setReproducedEncryptionContext(new HashMap<>())
          .setEncryptedDataKeys(SOME_EDK_LIST)
          .build();

  @Test
  public void
      GIVEN_CMM_does_not_add_encryption_context_AND_request_has_nonempty_encryption_context_WHEN_decryptMaterials_THEN_output_has_nonempty_encryption_context() {
    CryptoMaterialsManager anyNativeCMM = mock(CryptoMaterialsManager.class);

    // Given: native CMM does not set an encryptionContext on returned DecryptionMaterials objects
    DecryptionMaterials someDecryptionMaterialsWithoutEC =
        DecryptionMaterials.newBuilder()
            .setDataKey(mock(DataKey.class))
            .setTrailingSignatureKey(mock(PublicKey.class))
            .setEncryptionContext(new HashMap<>())
            .build();
    // Given: request with nonempty encryption context
    when(anyNativeCMM.decryptMaterials(SOME_DECRYPTION_MATERIALS_REQUEST_NON_EMPTY_EC))
        .thenReturn(someDecryptionMaterialsWithoutEC);

    // When: decryptMaterials
    CMMHandler handlerUnderTest = new CMMHandler(anyNativeCMM);
    DecryptionMaterialsHandler output =
        handlerUnderTest.decryptMaterials(
            SOME_DECRYPTION_MATERIALS_REQUEST_NON_EMPTY_EC, SOME_COMMITMENT_POLICY);

    // Then: output DecryptionMaterialsHandler has encryption context
    assertEquals(SOME_NON_EMPTY_ENCRYPTION_CONTEXT, output.getEncryptionContext());
  }

  @Test
  public void
      GIVEN_CMM_does_not_add_encryption_context_AND_request_has_empty_encryption_context_WHEN_decryptMaterials_THEN_output_has_empty_encryption_context() {
    CryptoMaterialsManager anyNativeCMM = mock(CryptoMaterialsManager.class);

    // Given: native CMM does not set an encryptionContext on returned DecryptionMaterials objects
    DecryptionMaterials someDecryptionMaterialsWithoutEC =
        DecryptionMaterials.newBuilder()
            .setDataKey(mock(DataKey.class))
            .setTrailingSignatureKey(mock(PublicKey.class))
            .setEncryptionContext(new HashMap<>())
            .build();
    // Given: request with empty encryption context
    when(anyNativeCMM.decryptMaterials(SOME_DECRYPTION_MATERIALS_REQUEST_EMPTY_EC))
        .thenReturn(someDecryptionMaterialsWithoutEC);

    // When: decryptMaterials
    CMMHandler handlerUnderTest = new CMMHandler(anyNativeCMM);
    DecryptionMaterialsHandler output =
        handlerUnderTest.decryptMaterials(
            SOME_DECRYPTION_MATERIALS_REQUEST_EMPTY_EC, SOME_COMMITMENT_POLICY);

    // Then: output DecryptionMaterialsHandler has empty encryption context
    assertTrue(output.getEncryptionContext().isEmpty());
  }

  @Test
  public void
      GIVEN_CMM_adds_encryption_context_AND_request_has_nonempty_encryption_context_WHEN_decryptMaterials_THEN_output_has_nonempty_encryption_context() {
    CryptoMaterialsManager anyNativeCMM = mock(CryptoMaterialsManager.class);

    // Given: native CMM sets encryptionContext on returned DecryptionMaterials objects
    DecryptionMaterials someDecryptionMaterialsWithoutEC =
        DecryptionMaterials.newBuilder()
            .setDataKey(mock(DataKey.class))
            .setTrailingSignatureKey(mock(PublicKey.class))
            .setEncryptionContext(SOME_NON_EMPTY_ENCRYPTION_CONTEXT)
            .build();
    // Given: request with nonempty encryption context
    when(anyNativeCMM.decryptMaterials(SOME_DECRYPTION_MATERIALS_REQUEST_NON_EMPTY_EC))
        .thenReturn(someDecryptionMaterialsWithoutEC);

    // When: decryptMaterials
    CMMHandler handlerUnderTest = new CMMHandler(anyNativeCMM);
    DecryptionMaterialsHandler output =
        handlerUnderTest.decryptMaterials(
            SOME_DECRYPTION_MATERIALS_REQUEST_NON_EMPTY_EC, SOME_COMMITMENT_POLICY);

    // Then: output DecryptionMaterialsHandler has nonempty encryption context
    assertEquals(SOME_NON_EMPTY_ENCRYPTION_CONTEXT, output.getEncryptionContext());
  }

  @Test
  public void
      GIVEN_CMM_adds_encryption_context_AND_request_has_empty_encryption_context_WHEN_decryptMaterials_THEN_output_has_empty_encryption_context() {
    CryptoMaterialsManager anyNativeCMM = mock(CryptoMaterialsManager.class);

    // Given: native CMM sets encryptionContext on returned DecryptionMaterials objects
    DecryptionMaterials someDecryptionMaterialsWithoutEC =
        DecryptionMaterials.newBuilder()
            .setDataKey(mock(DataKey.class))
            .setTrailingSignatureKey(mock(PublicKey.class))
            .setEncryptionContext(new HashMap<>())
            .build();
    // Given: request with empty encryption context
    when(anyNativeCMM.decryptMaterials(SOME_DECRYPTION_MATERIALS_REQUEST_EMPTY_EC))
        .thenReturn(someDecryptionMaterialsWithoutEC);

    // When: decryptMaterials
    CMMHandler handlerUnderTest = new CMMHandler(anyNativeCMM);
    DecryptionMaterialsHandler output =
        handlerUnderTest.decryptMaterials(
            SOME_DECRYPTION_MATERIALS_REQUEST_EMPTY_EC, SOME_COMMITMENT_POLICY);

    // Then: output DecryptionMaterialsHandler has empty encryption context
    assertTrue(output.getEncryptionContext().isEmpty());
  }
}
