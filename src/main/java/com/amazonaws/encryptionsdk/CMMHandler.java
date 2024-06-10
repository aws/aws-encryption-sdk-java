// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.*;

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
        // ESDK-Java 3.0 changed the expected behavior for CMMs.
        // After 3.0, the ESDK assumes that CMMs' implementations of decryptMaterials
        // will return DecryptionMaterials with a set encryptionContext attribute.
        // The default CMM's behavior was changed in 3.0 to set the encryptionContext attribute
        // with the value from the ciphertext's headers.
        // However, this assumption is not true for custom CMMs from earlier ESDK versions.
        //
        // After 3.0, CMMs MUST set the encryptionContext on the returned decryptMaterials.
        // If the materials' encryptionContext is empty but the request's is not,
        // we assume the CMM never set the decryptMaterials' encryptionContext attribute
        // and set its attribute from the request.
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
