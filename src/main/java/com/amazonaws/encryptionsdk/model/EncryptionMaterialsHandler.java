package com.amazonaws.encryptionsdk.model;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.internal.TrailingSignatureAlgorithm;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;

/**
 * Handler to abstract the differences between the original {@link EncryptionMaterials} and the
 * MPL's {@link software.amazon.cryptography.materialproviders.model.EncryptionMaterials}.
 */
public class EncryptionMaterialsHandler {
  EncryptionMaterials materials;
  software.amazon.cryptography.materialproviders.model.EncryptionMaterials mplMaterials;

  public EncryptionMaterialsHandler(EncryptionMaterials materials) {
    this.materials = materials;
  }

  public EncryptionMaterialsHandler(
      software.amazon.cryptography.materialproviders.model.EncryptionMaterials mplMaterials) {
    this.mplMaterials = mplMaterials;
  }

  public CryptoAlgorithm getAlgorithm() {
    if (materials != null) {
      return materials.getAlgorithm();
    } else {
      return CryptoAlgorithm.valueOf(mplMaterials.algorithmSuite().id().ESDK().name());
    }
  }

  public Map<String, String> getEncryptionContext() {
    if (materials != null) {
      return materials.getEncryptionContext();
    } else {
      return mplMaterials.encryptionContext();
    }
  }

  public List<KeyBlob> getEncryptedDataKeys() {
    if (materials != null) {
      return materials.getEncryptedDataKeys();
    } else {
      List<EncryptedDataKey> edks = mplMaterials.encryptedDataKeys();
      List<KeyBlob> keyBlobs = new ArrayList<>(edks.size());
      for (EncryptedDataKey edk : edks) {
        keyBlobs.add(
            new KeyBlob(
                edk.keyProviderId(), edk.keyProviderInfo().array(), edk.ciphertext().array()));
      }
      return keyBlobs;
    }
  }

  public SecretKey getCleartextDataKey() {
    if (materials != null) {
      return materials.getCleartextDataKey();
    } else {
      byte[] cacheDataKey = mplMaterials.plaintextDataKey().array();
      CryptoAlgorithm cryptoAlgorithm =
          CryptoAlgorithm.valueOf(mplMaterials.algorithmSuite().id().ESDK().name());
      return new SecretKeySpec(
          cacheDataKey, 0, cacheDataKey.length, cryptoAlgorithm.getDataKeyAlgo());
    }
  }

  public PrivateKey getTrailingSignatureKey() {
    if (materials != null) {
      return materials.getTrailingSignatureKey();
    } else {
      if (mplMaterials.signingKey() == null) {
        return null;
      }
      // Converts ByteBuffer to ECPrivateKey using the AlgorithmSuiteInfo
      return TrailingSignatureAlgorithm.forCryptoAlgorithm(mplMaterials.algorithmSuite())
          .privateKeyFromByteBuffer(mplMaterials.signingKey());
    }
  }

  public List<String> getRequiredEncryptionContextKeys() {
    if (materials != null) {
      return Collections.emptyList();
    } else {
      return mplMaterials.requiredEncryptionContextKeys();
    }
  }

  @Deprecated
  public List<MasterKey> getMasterKeys() {
    if (materials != null) {
      return materials.getMasterKeys();
    } else {
      // Return Empty List
      return Collections.emptyList();
    }
  }
}
