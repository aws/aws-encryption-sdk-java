// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsHandler;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsHandler;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.KeyBlob;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsOutput;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsOutput;

/**
 * Handler to abstract the differences between the original {@link CryptoMaterialsManager} and the
 * MPL's {@link ICryptographicMaterialsManager}.
 */
public class CMMHandler {
  CryptoMaterialsManager cmm = null;
  ICryptographicMaterialsManager mplCMM = null;

  public CMMHandler(CryptoMaterialsManager cmm) {
    Utils.assertNonNull(cmm, "cmm");
    this.cmm = cmm;
  }

  public CMMHandler(ICryptographicMaterialsManager mplCMM) {
    Utils.assertNonNull(mplCMM, "mplCMM");
    this.mplCMM = mplCMM;
  }

  public EncryptionMaterialsHandler getMaterialsForEncrypt(EncryptionMaterialsRequest request) {
    if (cmm != null && mplCMM == null) {
      return new EncryptionMaterialsHandler(cmm.getMaterialsForEncrypt(request));
    } else {
      GetEncryptionMaterialsInput input = getEncryptionMaterialsRequestInput(request);
      GetEncryptionMaterialsOutput output = mplCMM.GetEncryptionMaterials(input);
      return new EncryptionMaterialsHandler(output.encryptionMaterials());
    }
  }

  private GetEncryptionMaterialsInput getEncryptionMaterialsRequestInput(
      EncryptionMaterialsRequest request) {
    return GetEncryptionMaterialsInput.builder()
        .encryptionContext(request.getContext())
        .algorithmSuiteId(
            request.getRequestedAlgorithm() == null
                ? null
                : request.getRequestedAlgorithm().getAlgorithmSuiteId())
        .commitmentPolicy(request.getCommitmentPolicy().getMplCommitmentPolicy())
        .maxPlaintextLength(request.getPlaintextSize())
        .build();
  }

  public DecryptionMaterialsHandler decryptMaterials(
      DecryptionMaterialsRequest request, CommitmentPolicy commitmentPolicy) {
    if (cmm != null && mplCMM == null) {
      // This is an implementation of the legacy native CryptoMaterialsManager interface from ESDK-Java.
      DecryptionMaterials materials = cmm.decryptMaterials(request);
      if (materials.getEncryptionContext().isEmpty()
        && !request.getEncryptionContext().isEmpty()) {
        // If the request specified an encryption context,
        // and we are using the legacy native CMM,
        // add the encryptionContext to the materials.
        //
        // ESDK-Java 3.0 changed internals of decrypt behavior,
        // This code makes earlier CMM implementations compatible with post-3.0 behavior.
        //
        // Version 3.0 assumes that CMMs' implementations of decryptMaterials
        // will set an encryptionContext attribute on returned DecryptionMaterials.
        // The DefaultCryptoMaterialsManager's behavior was changed in 3.0.
        // It now sets the encryptionContext attribute with the value from the ciphertext's headers.
        //
        // But custom CMMs' behavior was not updated.
        // However, there is no custom CMM before version 3.0 that could set an encryptionContext attribute.
        // The encryptionContext attribute was only introduced to decryptMaterials objects
        // in ESDK 3.0, so no CMM could have configured this attribute before 3.0.
        // As a result, the ESDK assumes that any native CMM
        // that does not add encryptionContext to its decryptMaterials
        // SHOULD add encryptionContext to its decryptMaterials,
        //
        // If a custom CMM implementation conflicts with this assumption.
        // that CMM implementation MUST move to the MPL.
        materials = materials.toBuilder()
                .setEncryptionContext(request.getEncryptionContext())
                .build();
      }
      return new DecryptionMaterialsHandler(materials);
    } else {
      DecryptMaterialsInput input = getDecryptMaterialsInput(request, commitmentPolicy);
      DecryptMaterialsOutput output = mplCMM.DecryptMaterials(input);
      return new DecryptionMaterialsHandler(output.decryptionMaterials());
    }
  }

  private DecryptMaterialsInput getDecryptMaterialsInput(
      DecryptionMaterialsRequest request, CommitmentPolicy commitmentPolicy) {
    List<KeyBlob> keyBlobs = request.getEncryptedDataKeys();
    List<software.amazon.cryptography.materialproviders.model.EncryptedDataKey> edks =
        new ArrayList<>(keyBlobs.size());
    for (KeyBlob keyBlob : keyBlobs) {
      edks.add(
          EncryptedDataKey.builder()
              .keyProviderId(keyBlob.getProviderId())
              .keyProviderInfo(
                  ByteBuffer.wrap(
                      keyBlob.getProviderInformation(), 0, keyBlob.getProviderInformation().length))
              .ciphertext(
                  ByteBuffer.wrap(
                      keyBlob.getEncryptedDataKey(), 0, keyBlob.getEncryptedDataKey().length))
              .build());
    }

    return DecryptMaterialsInput.builder()
        .encryptionContext(request.getEncryptionContext())
        .reproducedEncryptionContext(request.getReproducedEncryptionContext())
        .algorithmSuiteId(request.getAlgorithm().getAlgorithmSuiteId())
        .commitmentPolicy(commitmentPolicy.getMplCommitmentPolicy())
        .encryptedDataKeys(edks)
        .build();
  }
}
