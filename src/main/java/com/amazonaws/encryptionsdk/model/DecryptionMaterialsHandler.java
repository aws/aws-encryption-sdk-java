package com.amazonaws.encryptionsdk.model;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.internal.TrailingSignatureAlgorithm;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Handler to abstract the differences between the original {@link DecryptionMaterials} and the
 * MPL's {@link software.amazon.cryptography.materialproviders.model.DecryptionMaterials}.
 */
public class DecryptionMaterialsHandler {
  private DecryptionMaterials materials;
  private software.amazon.cryptography.materialproviders.model.DecryptionMaterials mplMaterials;

  public DecryptionMaterialsHandler(DecryptionMaterials materials) {
    this.materials = materials;
    this.mplMaterials = null;
  }

  public DecryptionMaterialsHandler(
      software.amazon.cryptography.materialproviders.model.DecryptionMaterials mplMaterials) {
    this.mplMaterials = mplMaterials;
    this.materials = null;
  }

  public DataKey<?> getDataKey() {
    if (materials != null) {
      return materials.getDataKey();
    } else {
      byte[] cacheDataKey = mplMaterials.plaintextDataKey().array();
      SecretKey key =
          new SecretKeySpec(
              cacheDataKey,
              0,
              cacheDataKey.length,
              CryptoAlgorithm.valueOf(mplMaterials.algorithmSuite().id().ESDK().name())
                  .getDataKeyAlgo());
      return new DataKey<>(key, new byte[0], new byte[0], null);
    }
  }

  public PublicKey getTrailingSignatureKey() {
    if (materials != null) {
      return materials.getTrailingSignatureKey();
    } else {
      if (mplMaterials.verificationKey() == null) {
        return null;
      }
      // Converts ByteBuffer to ECPublicKey using the AlgorithmSuiteInfo
      return TrailingSignatureAlgorithm.forCryptoAlgorithm(mplMaterials.algorithmSuite())
          .decompressPublicKey(mplMaterials.verificationKey().array());
    }
  }

  public Map<String, String> getEncryptionContext() {
    if (materials != null) {
      return materials.getEncryptionContext();
    } else {
      return mplMaterials.encryptionContext();
    }
  }

  public List<String> getRequiredEncryptionContextKeys() {
    if (materials != null) {
      return Collections.emptyList();
    } else {
      return mplMaterials.requiredEncryptionContextKeys();
    }
  }
}
